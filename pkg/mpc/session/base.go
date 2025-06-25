package session

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc/party"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

type Curve string

type Purpose string

const (
	CurveSecp256k1 Curve = "secp256k1"
	CurveEd25519   Curve = "ed25519"

	PurposeKeygen  Purpose = "keygen"
	PurposeSign    Purpose = "sign"
	PurposeReshare Purpose = "reshare"
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(nodeID string) string
}

type KeyComposerFn func(id string) string

type Session interface {
	StartKeygen(ctx context.Context, send func(tss.Message), finish func([]byte))
	StartSigning(ctx context.Context, msg *big.Int, send func(tss.Message), finish func([]byte))
	StartResharing(
		ctx context.Context,
		oldPartyIDs []*tss.PartyID,
		newPartyIDs []*tss.PartyID,
		oldThreshold int,
		newThreshold int,
		send func(tss.Message),
		finish func([]byte),
	)

	GetSaveData(version int) ([]byte, error)
	GetPublicKey(data []byte) ([]byte, error)
	VerifySignature(msg []byte, signature []byte) (*common.SignatureData, error)

	PartyIDs() []*tss.PartyID
	Send(msg tss.Message)
	Listen()
	WaitReady(ctx context.Context) error
	SaveKey(participantPeerIDs []string, threshold int, version int, data []byte) (err error)
	ErrCh() chan error
	Close()
}

type session struct {
	walletID string
	party    party.Party

	broadcastSub messaging.Subscription
	directSub    messaging.Subscription
	pubSub       messaging.PubSub
	direct       messaging.DirectMessaging

	identityStore identity.Store
	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store

	topicComposer *TopicComposer
	composeKey    KeyComposerFn

	mu      sync.Mutex
	errCh   chan error
	readyCh chan struct{}
}

func NewSession(
	purpose Purpose,
	walletID string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	identityStore identity.Store,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
) *session {
	errCh := make(chan error, 1000)
	return &session{
		walletID:      walletID,
		pubSub:        pubSub,
		direct:        direct,
		identityStore: identityStore,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		errCh:         errCh,
		readyCh:       make(chan struct{}),
	}
}

func (s *session) PartyIDs() []*tss.PartyID {
	return s.party.PartyIDs()
}

func (s *session) ErrCh() chan error {
	return s.errCh
}

// Send is a wrapper around the party's Send method
// It signs the message and sends it to the remote party
func (s *session) Send(msg tss.Message) {
	data, routing, err := msg.WireBytes()
	if err != nil {
		s.errCh <- fmt.Errorf("failed to wire bytes: %w", err)
		return
	}

	tssMsg := types.NewTssMessage(s.walletID, data, routing.IsBroadcast, routing.From, routing.To)
	signature, err := s.identityStore.SignMessage(&tssMsg)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to sign message: %w", err)
		return
	}
	tssMsg.Signature = signature
	msgBytes, err := types.MarshalTssMessage(&tssMsg)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to marshal message: %w", err)
		return
	}
	round, _, err := s.party.ClassifyMsg(data)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to classify message: %w", err)
		return
	}
	toNodeIDs := make([]string, len(routing.To))
	for i, to := range routing.To {
		toNodeIDs[i] = getRoutingFromPartyID(to)
	}
	logger.Debug(
		"Sending message",
		"from",
		routing.From.Moniker,
		"to",
		toNodeIDs,
		"isBroadcast",
		routing.IsBroadcast,
		"round",
		round,
	)

	if routing.IsBroadcast && len(routing.To) == 0 {
		err := s.pubSub.Publish(s.topicComposer.ComposeBroadcastTopic(), msgBytes)
		if err != nil {
			s.errCh <- fmt.Errorf("failed to publish message: %w", err)
			return
		}
	} else {
		for _, to := range routing.To {
			nodeID := getRoutingFromPartyID(to)
			topic := s.topicComposer.ComposeDirectTopic(nodeID)
			err := s.direct.Send(topic, msgBytes)
			if err != nil {
				s.errCh <- fmt.Errorf("failed to send message: %w", err)
				return
			}
		}
	}
}

// Listen is a wrapper around the party's Listen method
// It subscribes to the broadcast and self direct topics
func (s *session) Listen() {
	selfDirectTopic := s.topicComposer.ComposeDirectTopic(getRoutingFromPartyID(s.party.PartyID()))
	var wg sync.WaitGroup
	wg.Add(2) // One for broadcast, one for direct

	broadcast := func() {
		defer wg.Done()
		sub, err := s.pubSub.Subscribe(
			s.topicComposer.ComposeBroadcastTopic(),
			func(natMsg *nats.Msg) {
				msg := natMsg.Data
				s.receive(msg)
			},
		)

		if err != nil {
			s.errCh <- fmt.Errorf("failed to subscribe to broadcast topic %s: %w", s.topicComposer.ComposeBroadcastTopic(), err)
			return
		}

		s.broadcastSub = sub
	}

	direct := func() {
		defer wg.Done()
		sub, err := s.direct.Listen(selfDirectTopic, func(msg []byte) {
			s.receive(msg)
		})

		if err != nil {
			s.errCh <- fmt.Errorf("failed to subscribe to direct topic %s: %w", s.topicComposer.ComposeDirectTopic(s.party.PartyID().String()), err)
			return
		}

		s.directSub = sub
	}

	go broadcast()
	go direct()

	// Wait for both subscriptions to be ready
	go func() {
		wg.Wait()
		close(s.readyCh)
	}()
}

// WaitReady waits for the session to be ready
func (s *session) WaitReady(ctx context.Context) error {
	select {
	case <-s.readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SaveKey saves the key to the keyinfo store and the kvstore
func (s *session) SaveKey(
	participantPeerIDs []string,
	threshold int,
	version int,
	data []byte,
) (err error) {
	keyInfo := keyinfo.KeyInfo{
		ParticipantPeerIDs: participantPeerIDs,
		Threshold:          threshold,
		Version:            version,
	}
	composeKey := s.composeKey(s.walletID)
	err = s.keyinfoStore.Save(composeKey, &keyInfo)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to save keyinfo: %w", err)
		return
	}

	err = s.kvstore.Put(fmt.Sprintf("%s-%d", composeKey, version), data)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to save key: %w", err)
		return
	}
	return
}

func (s *session) SetSaveData(saveBytes []byte) {
	s.party.SetSaveData(saveBytes)
}

// GetSaveData gets the key from the kvstore
func (s *session) GetSaveData(version int) ([]byte, error) {
	var key string
	composeKey := s.composeKey(s.walletID)
	if version == 0 {
		key = composeKey
	} else {
		key = fmt.Sprintf("%s-%d", composeKey, version)
	}
	data, err := s.kvstore.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return data, nil
}

func (s *session) Close() {
	// Close subscriptions first
	if s.broadcastSub != nil {
		s.broadcastSub.Unsubscribe()
	}
	if s.directSub != nil {
		s.directSub.Unsubscribe()
	}

	// Close party
	if s.party != nil {
		s.party.Close()
	}

	// Close error channel last
	select {
	case <-s.errCh:
		// Channel already closed
	default:
		close(s.errCh)
	}
}

// receive is a helper function that receives a message from the party
func (s *session) receive(rawMsg []byte) {
	msg, err := types.UnmarshalTssMessage(rawMsg)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to unmarshal message: %w", err)
		return
	}

	err = s.identityStore.VerifyMessage(msg)
	if err != nil {
		s.errCh <- fmt.Errorf("failed to verify message: %w", err)
		return
	}

	// Skip messages from self
	if msg.From.String() == s.party.PartyID().String() {
		return
	}

	toIDs := make([]string, len(msg.To))
	for i, id := range msg.To {
		toIDs[i] = id.String()
	}

	isBroadcast := msg.IsBroadcast && len(msg.To) == 0
	isToSelf := slices.Contains(toIDs, s.party.PartyID().String())

	if isBroadcast || isToSelf {
		round, _, err := s.party.ClassifyMsg(msg.MsgBytes)
		if err != nil {
			s.errCh <- fmt.Errorf("failed to classify message: %w", err)
			return
		}
		logger.Debug(
			"Received message",
			"from",
			msg.From.Moniker,
			"round",
			round,
			"isBroadcast",
			msg.IsBroadcast,
			"isToSelf",
			isToSelf,
		)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.party.InCh() <- *msg
	}
}
