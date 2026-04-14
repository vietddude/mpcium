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
	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/secure"
	rbconfig "github.com/fystack/mpcium/internal/relaybridge/config"
	routing "github.com/fystack/mpcium/internal/relaybridge/routing"
	rbtransport "github.com/fystack/mpcium/internal/relaybridge/transport"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/fystack/mpcium/pkg/logger"
)

type ResolvedSession struct {
	Session        rbtypes.SessionContext
	Protocol       mpcore.Protocol
	LocalIndex     uint16
	Participants   []mpcore.Participant
	PeerIdentities map[uint16]secure.PeerIdentity
}

type Runner struct {
	resolved          *ResolvedSession
	cfg               mpcore.SessionConfig
	transport         rbtransport.SessionEnvelopeTransport
	session           *secure.SecureSession
	sub               rbtransport.SessionEnvelopeSubscription
	readyPeers        map[string]struct{}
	peerReadyTimeout  time.Duration
	peerReadyInterval time.Duration
	pending           []protocol.Envelope
	started           bool
}

func ResolveContext(session rbtypes.SessionContext, participantID string) (*ResolvedSession, error) {
	if strings.TrimSpace(session.SessionID) == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(session.WalletID) == "" {
		return nil, fmt.Errorf("wallet_id is required")
	}
	if strings.TrimSpace(session.LocalParticipantID) == "" {
		return nil, fmt.Errorf("local_participant_id is required")
	}
	if session.LocalParticipantID != participantID {
		return nil, fmt.Errorf(
			"request local_participant_id %q does not match runtime participant_id %q",
			session.LocalParticipantID,
			participantID,
		)
	}
	protocolValue, err := parseProtocol(session.Protocol)
	if err != nil {
		return nil, err
	}
	if len(session.Participants) == 0 {
		return nil, fmt.Errorf("participants are required")
	}
	participants := make([]mpcore.Participant, 0, len(session.Participants))
	peerIdentities := make(map[uint16]secure.PeerIdentity, len(session.Participants))
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
		peerIdentities[uint16(i)] = secure.PeerIdentity{
			ParticipantID: participant.ID,
			PublicKey:     publicKey,
		}
		if participant.ID == session.LocalParticipantID {
			localIndex = i
		}
	}
	if localIndex < 0 {
		return nil, fmt.Errorf("local participant %q is not in participants", session.LocalParticipantID)
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
	sessionTransport rbtransport.SessionEnvelopeTransport,
	store secure.IdentityStore,
	appCfg rbconfig.Config,
) (*Runner, error) {
	secureSession, err := secure.NewSession(secure.SecureSessionConfig{
		Session:        cfg,
		IdentityStore:  store,
		IdentityRef:    appCfg.IdentityRef(),
		PeerIdentities: resolved.PeerIdentities,
	})
	if err != nil {
		return nil, err
	}
	return &Runner{
		resolved:          resolved,
		cfg:               cfg,
		transport:         sessionTransport,
		session:           secureSession,
		readyPeers:        map[string]struct{}{},
		peerReadyTimeout:  appCfg.PeerReadyTimeout(),
		peerReadyInterval: appCfg.PeerReadyInterval(),
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

	if err := r.waitForPeersReady(ctx, msgCh); err != nil {
		return nil, err
	}
	logger.Info(
		"mpcium-relaybridge all peers ready",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"peers", strings.Join(r.peerIDsExceptSelf(), ","),
	)
	outbound, result, err := r.session.Start()
	if err != nil {
		return nil, err
	}
	r.started = true
	logger.Info(
		"mpcium-relaybridge secure session started",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"outbound_messages", len(outbound),
	)
	if err := r.publishOutbound(outbound); err != nil {
		return nil, err
	}
	if result != nil {
		return result, nil
	}
	for _, env := range r.pending {
		res, err := r.handleEnvelope(env)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}
	}
	r.pending = nil

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg, ok := <-msgCh:
			if !ok {
				return nil, errors.New("session transport subscription closed")
			}
			if msg.Err != nil {
				return nil, msg.Err
			}
			if msg.Envelope.Session == nil {
				continue
			}
			res, err := r.handleEnvelope(msg.Envelope)
			if err != nil {
				return nil, err
			}
			if res != nil {
				return res, nil
			}
		}
	}
}

func (r *Runner) waitForPeersReady(
	ctx context.Context,
	msgCh <-chan rbtransport.SessionEnvelopeMessage,
) error {
	peers := r.peerIDsExceptSelf()
	if len(peers) == 0 {
		return nil
	}
	deadlineCtx, cancel := r.peerReadyContext(ctx)
	defer cancel()
	logger.Info(
		"mpcium-relaybridge waiting for peer readiness",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"expected_peers", strings.Join(peers, ","),
		"timeout", peerReadyTimeoutLabel(deadlineCtx, r.peerReadyTimeout),
		"interval", r.peerReadyInterval.String(),
	)

	ticker := time.NewTicker(r.peerReadyInterval)
	defer ticker.Stop()

	for {
		if r.hasAllReadyPeers(peers) {
			return nil
		}
		if err := r.publishReady(peers); err != nil {
			return err
		}
		select {
		case <-deadlineCtx.Done():
			logger.Error(
				"mpcium-relaybridge peer readiness timeout",
				deadlineCtx.Err(),
				"participant_id", r.resolved.Session.LocalParticipantID,
				"session_id", r.cfg.SessionID,
				"wallet_id", r.resolved.Session.WalletID,
				"expected_peers", strings.Join(peers, ","),
				"ready_peers", strings.Join(r.sortedReadyPeers(), ","),
			)
			return fmt.Errorf("timeout waiting for peer readiness: %w", deadlineCtx.Err())
		case <-ticker.C:
		case msg, ok := <-msgCh:
			if !ok {
				return errors.New("session transport subscription closed")
			}
			if msg.Err != nil {
				return msg.Err
			}
			if msg.Envelope.Session == nil {
				continue
			}
			if _, err := r.handleEnvelope(msg.Envelope); err != nil {
				return err
			}
		}
	}
}

func (r *Runner) publishReady(peers []string) error {
	for _, peerID := range peers {
		env := r.newSessionEnvelope([]string{peerID}, nil)
		logger.Debug(
			"mpcium-relaybridge publish ready",
			"participant_id", r.resolved.Session.LocalParticipantID,
			"peer_id", peerID,
			"session_id", r.cfg.SessionID,
			"wallet_id", r.resolved.Session.WalletID,
			"subject", r.outboundSubject(peerID),
		)
		if err := r.publishEnvelope(peerID, env); err != nil {
			return err
		}
	}
	return nil
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

func (r *Runner) publishEnvelope(peerID string, env protocol.Envelope) error {
	subject := r.outboundSubject(peerID)
	return r.transport.Publish(subject, env)
}

func (r *Runner) handleEnvelope(env protocol.Envelope) (*mpcore.Result, error) {
	if env.Type != protocol.EnvelopeTypeSession || env.Session == nil {
		return nil, nil
	}
	if env.Session.SessionID != r.cfg.SessionID ||
		env.Session.WalletID != r.resolved.Session.WalletID ||
		env.Session.Protocol != r.cfg.Protocol.String() ||
		env.Session.Operation != r.cfg.Operation.String() {
		logger.Info(
			"mpcium-relaybridge ignore session envelope due metadata mismatch",
			"participant_id", r.resolved.Session.LocalParticipantID,
			"from_peer", env.Session.SenderID,
			"expected_session_id", r.cfg.SessionID,
			"got_session_id", env.Session.SessionID,
			"expected_wallet_id", r.resolved.Session.WalletID,
			"got_wallet_id", env.Session.WalletID,
			"expected_protocol", r.cfg.Protocol.String(),
			"got_protocol", env.Session.Protocol,
			"expected_operation", r.cfg.Operation.String(),
			"got_operation", env.Session.Operation,
		)
		return nil, nil
	}
	firstReady := r.markPeerReady(env.Session.SenderID)
	if rbtransport.IsReadyEnvelope(env) {
		logReadyReceipt(r, env.Session.SenderID, firstReady)
		return nil, nil
	}
	if !r.started {
		logger.Info(
			"mpcium-relaybridge queue secure message before start",
			"participant_id", r.resolved.Session.LocalParticipantID,
			"from_peer", env.Session.SenderID,
			"session_id", r.cfg.SessionID,
			"wallet_id", r.resolved.Session.WalletID,
			"message_type", env.Session.Message.Type,
		)
		r.pending = append(r.pending, env)
		return nil, nil
	}
	if env.Session.Message.Type == "" {
		return nil, nil
	}
	logger.Debug(
		"mpcium-relaybridge accepted secure envelope",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", env.Session.SenderID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"message_type", env.Session.Message.Type,
	)
	logger.Debug(
		"mpcium-relaybridge apply secure message",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", env.Session.SenderID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"message_type", env.Session.Message.Type,
	)
	outbound, result, err := r.session.Apply(env.Session.Message)
	if err != nil {
		return nil, err
	}
	if err := r.publishOutbound(outbound); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *Runner) recipientsForMessage(message secure.Message) ([]string, error) {
	recipients, err := r.session.RecipientIDs(message)
	if err != nil {
		return nil, err
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

func (r *Runner) hasAllReadyPeers(peers []string) bool {
	for _, peerID := range peers {
		if _, ok := r.readyPeers[peerID]; !ok {
			return false
		}
	}
	return true
}

func (r *Runner) sortedReadyPeers() []string {
	peers := make([]string, 0, len(r.readyPeers))
	for peerID := range r.readyPeers {
		peers = append(peers, peerID)
	}
	return peers
}

func (r *Runner) markPeerReady(peerID string) bool {
	if strings.TrimSpace(peerID) == "" {
		return false
	}
	if _, exists := r.readyPeers[peerID]; exists {
		return false
	}
	r.readyPeers[peerID] = struct{}{}
	return true
}

func (r *Runner) peerReadyContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	if r.peerReadyTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.peerReadyTimeout)
}

func peerReadyTimeoutLabel(ctx context.Context, fallback time.Duration) string {
	if deadline, ok := ctx.Deadline(); ok {
		return time.Until(deadline).Round(time.Millisecond).String()
	}
	if fallback <= 0 {
		return "none"
	}
	return fallback.String()
}

func logReadyReceipt(r *Runner, peerID string, firstReady bool) {
	logFn := logger.Debug
	if firstReady {
		logFn = logger.Info
	}
	logFn(
		"mpcium-relaybridge received ready",
		"participant_id", r.resolved.Session.LocalParticipantID,
		"from_peer", peerID,
		"session_id", r.cfg.SessionID,
		"wallet_id", r.resolved.Session.WalletID,
		"ready_peers", strings.Join(r.sortedReadyPeers(), ","),
	)
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

func (r *Runner) newSessionEnvelope(recipientIDs []string, message *secure.Message) protocol.Envelope {
	payload := &protocol.SessionPayload{
		SessionID:    r.cfg.SessionID,
		WalletID:     r.resolved.Session.WalletID,
		KeyType:      mpcore.NormalizeKeyType(r.cfg.Protocol.String()),
		Protocol:     r.cfg.Protocol.String(),
		Operation:    r.cfg.Operation.String(),
		SenderID:     r.resolved.Session.LocalParticipantID,
		RecipientIDs: append([]string(nil), recipientIDs...),
	}
	if message != nil {
		payload.Message = *message
	}
	return protocol.Envelope{
		Version: protocol.EnvelopeVersion,
		Type:    protocol.EnvelopeTypeSession,
		Session: payload,
	}
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
