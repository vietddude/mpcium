package session

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fystack/mpcium-sdk/mpcore"
	"github.com/fystack/mpcium-sdk/secure"
	rbconfig "github.com/fystack/mpcium/internal/relaybridge/config"
	st "github.com/fystack/mpcium/internal/relaybridge/sessiontransport"
	"github.com/fystack/mpcium/pkg/logger"
	routing "github.com/fystack/mpcium/pkg/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
)

type ResolvedSession struct {
	Session        rbtypes.SessionContext
	Protocol       mpcore.Protocol
	LocalIndex     uint16
	Participants   []mpcore.Participant
	PeerIdentities map[string]secure.PeerIdentity
}

type Runner struct {
	resolved             *ResolvedSession
	cfg                  mpcore.SessionConfig
	transport            st.Transport
	session              secureSession
	sub                  st.Subscription
	keyExchangeSeenPeers map[string]struct{}
	phase                runnerPhase
}

type runnerPhase string

const (
	runnerPhaseKeyExchange = "key_exchange"
	runnerPhaseMPC         = "mpc"
	runnerPhaseDone        = "done"
)

const (
	keyExchangeReadyTimeout  = 10 * time.Second
	keyExchangeRetryInterval = 300 * time.Millisecond
)

type secureSession interface {
	StartKeyExchange() ([]secure.Message, error)
	StartMPC() ([]secure.Message, *mpcore.Result, error)
	Apply(msg secure.Message) ([]secure.Message, *mpcore.Result, error)
	Status() secure.Status
}

func ResolveContext(session rbtypes.SessionContext, participantID string) (*ResolvedSession, error) {
	if strings.TrimSpace(session.SessionID) == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(session.WalletID) == "" {
		return nil, fmt.Errorf("wallet_id is required")
	}
	participantID = strings.TrimSpace(participantID)
	if participantID == "" {
		return nil, fmt.Errorf("runtime participant_id is required")
	}
	protocolValue, err := parseProtocol(session.Protocol)
	if err != nil {
		return nil, err
	}
	if len(session.Participants) == 0 {
		return nil, fmt.Errorf("participants are required")
	}
	participants := make([]mpcore.Participant, 0, len(session.Participants))
	peerIdentities := make(map[string]secure.PeerIdentity, len(session.Participants))
	localIndex := -1
	for i, participant := range session.Participants {
		if strings.TrimSpace(participant.ID) == "" {
			return nil, fmt.Errorf("participants[%d].id is required", i)
		}
		uniqueKey, err := decodeHex(participant.UniqueKeyHex, false)
		if err != nil {
			return nil, fmt.Errorf("participants[%d].unique_key_hex: %w", i, err)
		}
		if len(uniqueKey) == 0 {
			uniqueKey = []byte(participant.ID)
		}
		publicKey, err := decodeHex(participant.IdentityPublicKeyHex, true)
		if err != nil {
			return nil, fmt.Errorf("participants[%d].identity_public_key_hex: %w", i, err)
		}
		participants = append(participants, mpcore.Participant{
			ID:        participant.ID,
			Moniker:   participant.Moniker,
			UniqueKey: uniqueKey,
		})
		peerIdentities[participant.ID] = secure.PeerIdentity{PublicKey: publicKey}
		if participant.ID == participantID {
			localIndex = i
			session.LocalParticipantID = participant.ID
		}
	}
	if localIndex < 0 {
		return nil, fmt.Errorf("runtime participant %q is not in participants", participantID)
	}
	return &ResolvedSession{
		Session:        session,
		Protocol:       protocolValue,
		LocalIndex:     uint16(localIndex),
		Participants:   participants,
		PeerIdentities: peerIdentities,
	}, nil
}

func NewRunner(
	resolved *ResolvedSession,
	cfg mpcore.SessionConfig,
	sessionTransport st.Transport,
	store secure.IdentityStore,
	appCfg rbconfig.Config,
) (*Runner, error) {
	secureSession, err := secure.NewSecureSession(secure.Config{
		Session:        cfg,
		IdentityStore:  store,
		IdentityRef:    appCfg.IdentityRef(),
		PeerIdentities: resolved.PeerIdentities,
	})
	if err != nil {
		return nil, fmt.Errorf("create secure session: %w", err)
	}
	return &Runner{
		resolved:             resolved,
		cfg:                  cfg,
		transport:            sessionTransport,
		session:              secureSession,
		keyExchangeSeenPeers: map[string]struct{}{},
		phase:                runnerPhaseKeyExchange,
	}, nil
}

func (r *Runner) Run(ctx context.Context) (*mpcore.Result, error) {
	subjects := r.inboundSubjects()
	logger.Info(
		"mpcium-relaybridge session subscribe",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"subjects", strings.Join(subjects, ","),
	)
	sub, err := r.transport.Subscribe(subjects)
	if err != nil {
		return nil, err
	}
	r.sub = sub
	defer func() {
		if r.sub != nil {
			_ = r.sub.Close()
		}
	}()
	msgCh := sub.Messages()

	keyExchangeOutbound, err := r.session.StartKeyExchange()
	if err != nil {
		return nil, err
	}
	logger.Info(
		"mpcium-relaybridge secure key exchange publish",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"outbound_messages", len(keyExchangeOutbound),
	)
	if err := r.runKeyExchangePhase(ctx, msgCh, keyExchangeOutbound); err != nil {
		return nil, err
	}
	return r.runMPCPhase(ctx, msgCh)
}

func (r *Runner) runKeyExchangePhase(
	ctx context.Context,
	msgCh <-chan st.Delivery,
	initialOutbound []secure.Message,
) error {
	if err := r.publishOutbound(initialOutbound); err != nil {
		return err
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, keyExchangeReadyTimeout)
	defer cancel()
	ticker := time.NewTicker(keyExchangeRetryInterval)
	defer ticker.Stop()

	for len(r.session.Status().WaitingForKeys) > 0 {
		select {
		case <-deadlineCtx.Done():
			return fmt.Errorf("timeout waiting for key exchange readiness: %w", deadlineCtx.Err())
		case <-ticker.C:
			waiting := strings.Join(r.session.Status().WaitingForKeys, ",")
			logger.Debug(
				"mpcium-relaybridge retry key exchange publish",
				"participant_id", r.resolved.Session.LocalParticipantID,
				"session_id", r.cfg.SessionID,
				"wallet_id", r.resolved.Session.WalletID,
				"waiting_for_keys", waiting,
			)
			if err := r.publishOutbound(initialOutbound); err != nil {
				return err
			}
		case msg, ok := <-msgCh:
			if !ok {
				return errors.New("session transport subscription closed")
			}
			if msg.Err != nil {
				return msg.Err
			}
			if !r.matchesEnvelope(msg.Payload) {
				continue
			}
			if err := r.handleKeyExchangeEnvelope(msg.Payload); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) runMPCPhase(
	ctx context.Context,
	msgCh <-chan st.Delivery,
) (*mpcore.Result, error) {
	r.phase = runnerPhaseMPC
	outbound, result, err := r.session.StartMPC()
	if err != nil {
		return nil, err
	}
	logger.Info(
		"mpcium-relaybridge secure mpc started",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"outbound_messages", len(outbound),
	)
	if err := r.publishOutbound(outbound); err != nil {
		return nil, err
	}
	if result != nil {
		r.phase = runnerPhaseDone
		return result, nil
	}

	for {
		env, err := r.nextEnvelope(ctx, msgCh)
		if err != nil {
			return nil, err
		}
		res, err := r.handleMPCEnvelope(env)
		if err != nil {
			return nil, err
		}
		if res != nil {
			r.phase = runnerPhaseDone
			return res, nil
		}
	}
}

func (r *Runner) publishOutbound(messages []secure.Message) error {
	for _, message := range messages {
		recipients, err := r.recipientsForMessage(message)
		if err != nil {
			return err
		}
		for _, peerID := range recipients {
			cloned := cloneSecureMessage(message)
			env := r.newSessionEnvelope([]string{peerID}, cloned)
			logger.Debug(
				"mpcium-relaybridge publish secure message",
				"participant_id", r.resolved.Session.LocalParticipantID,
				"peer_id", peerID,
				"session_id", r.cfg.SessionID,
				"wallet_id", r.resolved.Session.WalletID,
				"message_type", message.Type,
				"subject", r.outboundSubject(peerID),
			)
			if err := r.publishEnvelope(peerID, env); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) publishEnvelope(peerID string, env st.Payload) error {
	subject := r.outboundSubject(peerID)
	return r.transport.Publish(subject, env)
}

func (r *Runner) nextEnvelope(
	ctx context.Context,
	msgCh <-chan st.Delivery,
) (st.Payload, error) {
	for {
		select {
		case <-ctx.Done():
			return st.Payload{}, ctx.Err()
		case msg, ok := <-msgCh:
			if !ok {
				return st.Payload{}, errors.New("session transport subscription closed")
			}
			if msg.Err != nil {
				return st.Payload{}, msg.Err
			}
			if !r.matchesEnvelope(msg.Payload) {
				continue
			}
			return msg.Payload, nil
		}
	}
}

func (r *Runner) matchesEnvelope(env st.Payload) bool {
	if env.SessionID == r.cfg.SessionID &&
		env.WalletID == r.resolved.Session.WalletID &&
		env.Protocol == r.cfg.Protocol.String() &&
		env.Operation == r.cfg.Operation.String() {
		return true
	}
	logger.Info(
		"mpcium-relaybridge ignore session envelope due metadata mismatch",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", env.SenderID,
		"expected_session_id", r.cfg.SessionID,
		"got_session_id", env.SessionID,
		"expected_wallet_id", r.resolved.Session.WalletID,
		"got_wallet_id", env.WalletID,
		"expected_protocol", r.cfg.Protocol.String(),
		"got_protocol", env.Protocol,
		"expected_operation", r.cfg.Operation.String(),
		"got_operation", env.Operation,
	)
	return false
}

func (r *Runner) handleKeyExchangeEnvelope(env st.Payload) error {
	if !isKeyExchangeSessionEnvelope(env) {
		return fmt.Errorf("received %s during key exchange phase", describeEnvelope(env))
	}
	r.markPeerKeyExchange(env.SenderID)
	logger.Debug(
		"mpcium-relaybridge accepted secure envelope",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", env.SenderID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"message_type", env.Message.Type,
	)
	outbound, result, err := r.session.Apply(env.Message)
	if err != nil {
		return err
	}
	if result != nil {
		return fmt.Errorf("unexpected result during key exchange phase")
	}
	if err := r.publishOutbound(outbound); err != nil {
		return err
	}
	return nil
}

func (r *Runner) handleMPCEnvelope(env st.Payload) (*mpcore.Result, error) {
	if isKeyExchangeSessionEnvelope(env) {
		return nil, fmt.Errorf("received key exchange during mpc phase")
	}
	if env.Message.Type == "" {
		return nil, fmt.Errorf("received empty secure message during mpc phase")
	}
	logger.Debug(
		"mpcium-relaybridge accepted secure envelope",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", env.SenderID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"message_type", env.Message.Type,
	)
	logger.Debug(
		"mpcium-relaybridge apply secure message",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", env.SenderID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"message_type", env.Message.Type,
	)
	outbound, result, err := r.session.Apply(env.Message)
	if err != nil {
		return nil, err
	}
	if err := r.publishOutbound(outbound); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *Runner) recipientsForMessage(message secure.Message) ([]string, error) {
	var recipients []string
	switch message.Type {
	case secure.MessageTypeSignedBroadcast:
		recipients = r.peerIDsExceptSelf()
	case secure.MessageTypeEncryptedDirect:
		if message.EncryptedDirect == nil {
			return nil, fmt.Errorf("encrypted direct payload is required")
		}
		for _, participantID := range message.EncryptedDirect.Message.RecipientParticipantIDs {
			participantID = strings.TrimSpace(participantID)
			if participantID == "" {
				return nil, fmt.Errorf("encrypted direct recipient participant ID is required")
			}
			recipients = append(recipients, participantID)
		}
	default:
		return nil, fmt.Errorf("unsupported secure message type %q", message.Type)
	}
	for _, recipientID := range recipients {
		if recipientID != r.resolved.Session.LocalParticipantID {
			continue
		}
		return nil, fmt.Errorf(
			"secure session produced local recipient %q for message type %q",
			r.resolved.Session.LocalParticipantID,
			message.Type,
		)
	}
	return recipients, nil
}

func (r *Runner) peerIDsExceptSelf() []string {
	peers := make([]string, 0, len(r.resolved.Participants))
	for _, participant := range r.resolved.Participants {
		if participant.ID != r.resolved.Session.LocalParticipantID {
			peers = append(peers, participant.ID)
		}
	}
	return peers
}

func (r *Runner) markPeerKeyExchange(peerID string) bool {
	if strings.TrimSpace(peerID) == "" {
		return false
	}
	if _, exists := r.keyExchangeSeenPeers[peerID]; exists {
		return false
	}
	r.keyExchangeSeenPeers[peerID] = struct{}{}
	return true
}

func (r *Runner) inboundSubjects() []string {
	subjects := make([]string, 0, 2)
	localID := r.resolved.Session.LocalParticipantID
	walletID := r.resolved.Session.WalletID
	protocol := r.resolved.Session.Protocol
	operation := rbtypes.Operation(r.cfg.Operation.String())
	sessionID := r.cfg.SessionID

	if !isExternalParticipantID(r.resolved.Session.Participants, localID) {
		subjects = append(subjects, routing.DirectSessionSubject(localID, walletID, protocol, operation, sessionID))
	}
	subjects = append(subjects, routing.RelayInboundSessionSubject(localID, walletID, protocol, operation, sessionID))
	return subjects
}

func (r *Runner) outboundSubject(peerID string) string {
	protocol := r.resolved.Session.Protocol
	operation := rbtypes.Operation(r.cfg.Operation.String())
	if isExternalParticipantID(r.resolved.Session.Participants, peerID) {
		return routing.RelayOutboundSessionSubject(peerID, r.resolved.Session.WalletID, protocol, operation, r.cfg.SessionID)
	}
	return routing.DirectSessionSubject(peerID, r.resolved.Session.WalletID, protocol, operation, r.cfg.SessionID)
}

func (r *Runner) newSessionEnvelope(recipientIDs []string, message *secure.Message) st.Payload {
	payload := st.Payload{
		SessionID:    r.cfg.SessionID,
		WalletID:     r.resolved.Session.WalletID,
		Protocol:     r.cfg.Protocol.String(),
		Operation:    r.cfg.Operation.String(),
		SenderID:     r.resolved.Session.LocalParticipantID,
		RecipientIDs: append([]string(nil), recipientIDs...),
	}
	if message != nil {
		payload.Message = *message
	}
	return payload
}

func parseProtocol(value rbtypes.Protocol) (mpcore.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case string(rbtypes.ProtocolECDSA):
		return mpcore.ProtocolECDSA, nil
	case string(rbtypes.ProtocolEdDSA):
		return mpcore.ProtocolEdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", value)
	}
}

func decodeHex(value string, required bool) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return nil, fmt.Errorf("value is required")
		}
		return nil, nil
	}
	return hex.DecodeString(value)
}

func cloneSecureMessage(message secure.Message) *secure.Message {
	blob, err := json.Marshal(message)
	if err != nil {
		return &message
	}
	var cloned secure.Message
	if err := json.Unmarshal(blob, &cloned); err != nil {
		return &message
	}
	return &cloned
}

func describeEnvelope(env st.Payload) string {
	if isKeyExchangeSessionEnvelope(env) {
		return "key exchange message"
	}
	if env.Message.Type == "" {
		return "empty secure message"
	}
	return fmt.Sprintf("secure message type %q", env.Message.Type)
}

func isKeyExchangeSessionEnvelope(env st.Payload) bool {
	msg := env.Message
	return msg.Type == secure.MessageTypeSignedBroadcast &&
		msg.SignedBroadcast != nil &&
		msg.SignedBroadcast.Kind == secure.BroadcastKindKeyExchange
}

func isExternalParticipantID(participants []rbtypes.Participant, participantID string) bool {
	for _, participant := range participants {
		if participant.ID != participantID {
			continue
		}
		switch participant.ParticipantType {
		case rbtypes.ParticipantServer, rbtypes.ParticipantMobile:
			return true
		default:
			return false
		}
	}
	return false
}
