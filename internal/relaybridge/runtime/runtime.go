package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/fystack/mpcium-sdk/secure"
	rbconfig "github.com/fystack/mpcium/internal/relaybridge/config"
	routing "github.com/fystack/mpcium/internal/relaybridge/routing"
	rbservice "github.com/fystack/mpcium/internal/relaybridge/service"
	rbstorage "github.com/fystack/mpcium/internal/relaybridge/storage"
	rbtransport "github.com/fystack/mpcium/internal/relaybridge/transport"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type keyShareStore interface {
	rbstorage.KeyShareStorage
	io.Closer
}

type identityStore interface {
	secure.IdentityStore
	io.Closer
}

type sessionService interface {
	RunKeygen(ctx context.Context, req rbtypes.KeygenRequest) (*rbtypes.KeygenResult, error)
	RunSign(ctx context.Context, req rbtypes.SignRequest) (*rbtypes.SignResult, error)
}

type Runtime struct {
	cfg           rbconfig.Config
	natsConn      *nats.Conn
	shareStore    keyShareStore
	identityStore identityStore
	service       sessionService
	keygenBroker  messaging.MessageBroker
	signBroker    messaging.MessageBroker
	resultJS      jetstream.JetStream
	keygenSub     messaging.MessageSubscription
	signSub       messaging.MessageSubscription
	mu            sync.Mutex
	activeRuns    map[string]struct{}
	keygenGate    chan struct{}
}

func New(ctx context.Context, cfg rbconfig.Config) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	nc, err := connectNATS(cfg.NATS)
	if err != nil {
		return nil, err
	}
	shareStore, err := rbstorage.NewShareStore(cfg.KeyShareStorePath(), cfg.Storage.AgePassphrase)
	if err != nil {
		nc.Close()
		return nil, err
	}
	identityStore, err := rbstorage.NewLegacyIdentityStore(cfg.IdentityStorePath(), cfg.Storage.AgePassphrase)
	if err != nil {
		_ = shareStore.Close()
		nc.Close()
		return nil, err
	}
	svc, err := rbservice.New(cfg, shareStore, identityStore, rbtransport.NewNATS(nc))
	if err != nil {
		_ = shareStore.Close()
		nc.Close()
		return nil, err
	}

	keygenBroker, err := messaging.NewJetStreamBroker(
		ctx,
		nc,
		routing.KeygenRequestStream,
		[]string{routing.KeygenRequestTopic()},
		messaging.WithMaxAckPending(maxOrDefault(cfg.Consumer.MaxConcurrentKeygen, 2)),
	)
	if err != nil {
		_ = shareStore.Close()
		nc.Close()
		return nil, err
	}
	signBroker, err := messaging.NewJetStreamBroker(
		ctx,
		nc,
		routing.SignRequestStream,
		[]string{routing.SignRequestTopic()},
		messaging.WithMaxAckPending(maxOrDefault(cfg.Consumer.MaxConcurrentSign, 4)),
	)
	if err != nil {
		_ = keygenBroker.Close()
		_ = shareStore.Close()
		nc.Close()
		return nil, err
	}
	resultJS, err := newResultJetStream(nc)
	if err != nil {
		_ = signBroker.Close()
		_ = keygenBroker.Close()
		_ = shareStore.Close()
		nc.Close()
		return nil, err
	}
	return &Runtime{
		cfg:           cfg,
		natsConn:      nc,
		shareStore:    shareStore,
		identityStore: identityStore,
		service:       svc,
		keygenBroker:  keygenBroker,
		signBroker:    signBroker,
		resultJS:      resultJS,
		activeRuns:    make(map[string]struct{}),
		keygenGate:    make(chan struct{}, 1),
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	keygenSub, err := r.keygenBroker.CreateSubscription(
		ctx,
		routing.KeygenConsumerStream+"."+r.cfg.Runtime.ParticipantID,
		routing.KeygenRequestFilterSubject(r.cfg.Runtime.ParticipantID),
		r.handleKeygen,
	)
	if err != nil {
		return err
	}
	r.keygenSub = keygenSub

	signSub, err := r.signBroker.CreateSubscription(
		ctx,
		routing.SignConsumerStream+"."+r.cfg.Runtime.ParticipantID,
		routing.SignRequestFilterSubject(r.cfg.Runtime.ParticipantID),
		r.handleSign,
	)
	if err != nil {
		return err
	}
	r.signSub = signSub

	logger.Info(
		"mpcium-relaybridge runtime started",
		"participant_id", r.cfg.Runtime.ParticipantID,
		"keygen_subject", routing.KeygenRequestFilterSubject(r.cfg.Runtime.ParticipantID),
		"sign_subject", routing.SignRequestFilterSubject(r.cfg.Runtime.ParticipantID),
	)
	<-ctx.Done()
	return nil
}

func (r *Runtime) Close() error {
	if r.keygenSub != nil {
		_ = r.keygenSub.Unsubscribe()
	}
	if r.signSub != nil {
		_ = r.signSub.Unsubscribe()
	}
	if r.keygenBroker != nil {
		_ = r.keygenBroker.Close()
	}
	if r.signBroker != nil {
		_ = r.signBroker.Close()
	}
	if r.shareStore != nil {
		_ = r.shareStore.Close()
	}
	if r.identityStore != nil {
		_ = r.identityStore.Close()
	}
	if r.natsConn != nil && !r.natsConn.IsClosed() {
		return r.natsConn.Drain()
	}
	return nil
}

func (r *Runtime) KeyShareStore() rbstorage.KeyShareStorage {
	return r.shareStore
}

func (r *Runtime) handleKeygen(msg jetstream.Msg) {
	target, err := routing.ParseDirectRequestSubject(msg.Subject())
	if err != nil {
		logger.Error("Failed to parse relaybridge keygen request subject", err, "subject", msg.Subject())
		_ = msg.Ack()
		return
	}

	var req rbtypes.KeygenRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		logger.Error("Failed to decode relaybridge keygen request", err)
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if err := applyRequestTarget(&req.Session, target); err != nil {
		logger.Error("Invalid relaybridge keygen request target", err, "subject", msg.Subject())
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if !shouldHandleParticipants(req.Session.Participants, r.cfg.Runtime.ParticipantID) {
		_ = msg.Ack()
		return
	}
	r.acquireKeygenGate()
	defer r.releaseKeygenGate()
	runKey := sessionRunKey(req.Session)
	if !r.tryStartRun(runKey) {
		logger.Info(
			"Skip duplicate relaybridge keygen request while session is active",
			"participant_id", r.cfg.Runtime.ParticipantID,
			"subject", msg.Subject(),
			"session_id", req.Session.SessionID,
			"wallet_id", req.Session.WalletID,
		)
		_ = msg.Ack()
		return
	}
	defer r.finishRun(runKey)

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.RequestTimeout())
	defer cancel()
	result, err := r.service.RunKeygen(ctx, req)
	if err != nil {
		logger.Error(
			"mpcium-relaybridge keygen failed",
			err,
			"participant_id", r.cfg.Runtime.ParticipantID,
			"subject", msg.Subject(),
			"session_id", req.Session.SessionID,
			"wallet_id", req.Session.WalletID,
		)
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}

	if shouldReportParticipants(req.Session.Participants, r.cfg.Runtime.ParticipantID) {
		if err := r.publishKeygenResult(msg, *result); err != nil {
			logger.Error("Failed to publish relaybridge keygen result", err)
			_ = msg.Nak()
			return
		}
	}
	_ = msg.Ack()
}

func (r *Runtime) handleSign(msg jetstream.Msg) {
	target, err := routing.ParseDirectRequestSubject(msg.Subject())
	if err != nil {
		logger.Error("Failed to parse relaybridge sign request subject", err, "subject", msg.Subject())
		_ = msg.Ack()
		return
	}

	var req rbtypes.SignRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		logger.Error("Failed to decode relaybridge sign request", err)
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if err := applyRequestTarget(&req.Session, target); err != nil {
		logger.Error("Invalid relaybridge sign request target", err, "subject", msg.Subject())
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}

	recipients, err := selectedParticipants(req.Session.Participants, req.SignerIndexes)
	if err != nil {
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if !shouldHandleParticipants(recipients, r.cfg.Runtime.ParticipantID) {
		_ = msg.Ack()
		return
	}
	runKey := sessionRunKey(req.Session)
	if !r.tryStartRun(runKey) {
		logger.Info(
			"Skip duplicate relaybridge sign request while session is active",
			"participant_id", r.cfg.Runtime.ParticipantID,
			"subject", msg.Subject(),
			"session_id", req.Session.SessionID,
			"wallet_id", req.Session.WalletID,
		)
		_ = msg.Ack()
		return
	}
	defer r.finishRun(runKey)

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.RequestTimeout())
	defer cancel()
	result, err := r.service.RunSign(ctx, req)
	if err != nil {
		logger.Error(
			"mpcium-relaybridge sign failed",
			err,
			"participant_id", r.cfg.Runtime.ParticipantID,
			"subject", msg.Subject(),
			"session_id", req.Session.SessionID,
			"wallet_id", req.Session.WalletID,
		)
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}

	if shouldReportParticipants(recipients, r.cfg.Runtime.ParticipantID) {
		if err := r.publishSignResult(msg, *result); err != nil {
			logger.Error("Failed to publish relaybridge sign result", err)
			_ = msg.Nak()
			return
		}
	}
	_ = msg.Ack()
}

func (r *Runtime) publishKeygenResult(msg jetstream.Msg, result rbtypes.KeygenResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	clientID := msg.Headers().Get(event.ClientIDHeader)
	return publishResult(r.resultJS, routing.KeygenResultSubject(clientID, result.SessionID), payload, "relaybridge:keygen:"+result.SessionID)
}

func (r *Runtime) publishKeygenError(msg jetstream.Msg, req rbtypes.KeygenRequest, err error) {
	result := rbtypes.KeygenResult{
		SessionID:   req.Session.SessionID,
		WalletID:    req.Session.WalletID,
		Protocol:    string(req.Session.Protocol),
		ResultType:  event.ResultTypeError,
		ErrorReason: err.Error(),
		ErrorCode:   event.GetErrorCodeFromError(err),
	}
	if publishErr := r.publishKeygenResult(msg, result); publishErr != nil {
		logger.Error("Failed to publish relaybridge keygen error result", publishErr)
	}
}

func (r *Runtime) publishSignResult(msg jetstream.Msg, result rbtypes.SignResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	clientID := msg.Headers().Get(event.ClientIDHeader)
	return publishResult(r.resultJS, routing.SignResultSubject(clientID, result.SessionID), payload, "relaybridge:sign:"+result.SessionID)
}

func (r *Runtime) publishSignError(msg jetstream.Msg, req rbtypes.SignRequest, err error) {
	result := rbtypes.SignResult{
		SessionID:   req.Session.SessionID,
		WalletID:    req.Session.WalletID,
		Protocol:    string(req.Session.Protocol),
		ResultType:  event.ResultTypeError,
		ErrorReason: err.Error(),
		ErrorCode:   event.GetErrorCodeFromError(err),
	}
	if publishErr := r.publishSignResult(msg, result); publishErr != nil {
		logger.Error("Failed to publish relaybridge sign error result", publishErr)
	}
}

func applyRequestTarget(session *rbtypes.SessionContext, target routing.RequestTarget) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		session.SessionID = target.SessionID
	} else if session.SessionID != target.SessionID {
		return fmt.Errorf("session.session_id %q does not match request target %q", session.SessionID, target.SessionID)
	}
	if strings.TrimSpace(session.WalletID) == "" {
		session.WalletID = target.WalletID
	} else if session.WalletID != target.WalletID {
		return fmt.Errorf("session.wallet_id %q does not match request target %q", session.WalletID, target.WalletID)
	}
	if strings.TrimSpace(string(session.Protocol)) == "" {
		session.Protocol = target.Protocol
	} else if session.Protocol != target.Protocol {
		return fmt.Errorf("session.protocol %q does not match request target %q", session.Protocol, target.Protocol)
	}
	session.Operation = target.Operation
	session.LocalParticipantID = target.ParticipantID
	return nil
}

func shouldHandleParticipants(participants []rbtypes.Participant, participantID string) bool {
	for _, participant := range participants {
		if participant.ID == participantID {
			return true
		}
	}
	return false
}

func shouldReportParticipants(participants []rbtypes.Participant, participantID string) bool {
	return preferredReporter(participants) == participantID
}

func preferredReporter(participants []rbtypes.Participant) string {
	if len(participants) == 0 {
		return ""
	}
	for _, participant := range participants {
		if participant.ParticipantType == rbtypes.ParticipantNode || participant.ParticipantType == "" {
			return participant.ID
		}
	}
	return participants[0].ID
}

func selectedParticipants(participants []rbtypes.Participant, signerIndexes []uint16) ([]rbtypes.Participant, error) {
	selected := make([]rbtypes.Participant, 0, len(signerIndexes))
	seen := make(map[uint16]struct{}, len(signerIndexes))
	for _, idx := range signerIndexes {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		if int(idx) >= len(participants) {
			return nil, fmt.Errorf("signer index %d out of range", idx)
		}
		selected = append(selected, participants[idx])
	}
	return selected, nil
}

func newResultJetStream(nc *nats.Conn) (jetstream.JetStream, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	_, err = js.CreateOrUpdateStream(context.Background(), jetstream.StreamConfig{
		Name:        routing.ResultStreamName,
		Description: "Stream for " + routing.ResultStreamName,
		Subjects:    routing.ResultStreamSubjects(),
		MaxBytes:    100_000_000,
		Storage:     jetstream.FileStorage,
		Retention:   jetstream.WorkQueuePolicy,
	})
	if err != nil {
		return nil, err
	}
	return js, nil
}

func publishResult(js jetstream.JetStream, subject string, payload []byte, idempotencyKey string) error {
	if js == nil {
		return fmt.Errorf("result jetstream context is required")
	}
	msg := &nats.Msg{
		Subject: subject,
		Data:    payload,
	}
	if idempotencyKey != "" {
		msg.Header = nats.Header{}
		msg.Header.Set("Nats-Msg-Id", idempotencyKey)
	}
	_, err := js.PublishMsg(context.Background(), msg)
	return err
}

func connectNATS(cfg rbconfig.NATSConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
	}
	if cfg.Username != "" || cfg.Password != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	return nats.Connect(cfg.URL, opts...)
}

func maxOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func sessionRunKey(session rbtypes.SessionContext) string {
	return strings.TrimSpace(session.SessionID) + "::" + strings.TrimSpace(session.LocalParticipantID)
}

func (r *Runtime) tryStartRun(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.activeRuns[key]; exists {
		return false
	}
	r.activeRuns[key] = struct{}{}
	return true
}

func (r *Runtime) finishRun(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.activeRuns, key)
}

func (r *Runtime) acquireKeygenGate() {
	if r == nil || r.keygenGate == nil {
		return
	}
	r.keygenGate <- struct{}{}
}

func (r *Runtime) releaseKeygenGate() {
	if r == nil || r.keygenGate == nil {
		return
	}
	<-r.keygenGate
}
