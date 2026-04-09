package sdkflow

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ecdsakeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium-sdk/mpcore"
	"github.com/fystack/mpcium-sdk/secure"
	sdkstore "github.com/fystack/mpcium-sdk/store"
	"github.com/fystack/mpcium/internal/relay"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
)

const relayTail = "sdkflow"

type Service struct {
	cfg            Config
	natsConn       *nats.Conn
	store          *Store
	identityStore  secure.IdentityStore
	ecdsaPreparams []byte
}

func NewService(cfg Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	preparams, err := ensureECDSAPreparams(cfg)
	if err != nil {
		return nil, fmt.Errorf("prepare ecdsa preparams: %w", err)
	}
	nc, err := connectNATS(cfg.NATS)
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:            cfg,
		natsConn:       nc,
		store:          NewStore(cfg.Storage.RootDir),
		identityStore:  &identityStore{inner: sdkstore.NewFileStore(filepath.Join(cfg.Runtime.IdentityStoreDir, "identity"))},
		ecdsaPreparams: preparams,
	}, nil
}

func (s *Service) Close() error {
	if s.natsConn != nil && !s.natsConn.IsClosed() {
		return s.natsConn.Drain()
	}
	return nil
}

func (s *Service) RunKeygen(ctx context.Context, req KeygenRequest) (*KeygenResult, error) {
	resolved, err := s.resolveSession(req.Session)
	if err != nil {
		return nil, err
	}
	cfg := mpcore.SessionConfig{
		SessionID:          resolved.Session.SessionID,
		Protocol:           resolved.Protocol,
		Operation:          mpcore.OperationKeygen,
		Participants:       resolved.Participants,
		LocalIndex:         resolved.LocalIndex,
		Threshold:          resolved.Session.Threshold,
		KeyID:              resolved.Session.KeyID,
		ECDSAPreparamsBlob: s.ecdsaPreparams,
	}
	result, err := s.runSecureSession(ctx, resolved, cfg)
	if err != nil {
		return nil, err
	}
	if result == nil || len(result.ShareBlob) == 0 {
		return nil, fmt.Errorf("keygen completed without share")
	}
	ref, err := s.store.SaveShare(req.Session.Protocol, resolved.Session.KeyID, result.ShareBlob)
	if err != nil {
		return nil, err
	}
	pubKey, err := derivePublicKey(req.Session.Protocol, result.ShareBlob, s.ecdsaPreparams)
	if err != nil {
		return nil, err
	}
	return &KeygenResult{
		SessionID:  resolved.Session.SessionID,
		WalletID:   resolved.Session.WalletID,
		KeyID:      resolved.Session.KeyID,
		Protocol:   resolved.Session.Protocol,
		ShareRef:   ref,
		PubKey:     pubKey,
		ResultType: event.ResultTypeSuccess,
	}, nil
}

func (s *Service) RunSign(ctx context.Context, req SignRequest) (*SignResult, error) {
	resolved, err := s.resolveSession(req.Session)
	if err != nil {
		return nil, err
	}
	shareBlob, _, err := s.store.LoadShare(req.Session.Protocol, resolved.Session.KeyID)
	if err != nil {
		return nil, err
	}
	messageDigest, err := decodeHex(req.MessageDigestHex, true)
	if err != nil {
		return nil, fmt.Errorf("message_digest_hex: %w", err)
	}
	chainCode, err := decodeHex(req.ChainCodeHex, false)
	if err != nil {
		return nil, fmt.Errorf("chain_code_hex: %w", err)
	}
	cfg := mpcore.SessionConfig{
		SessionID:          resolved.Session.SessionID,
		Protocol:           resolved.Protocol,
		Operation:          mpcore.OperationSign,
		Participants:       resolved.Participants,
		LocalIndex:         resolved.LocalIndex,
		Threshold:          resolved.Session.Threshold,
		KeyID:              resolved.Session.KeyID,
		SignerIndexes:      append([]uint16(nil), req.SignerIndexes...),
		MessageDigest:      messageDigest,
		ChainCode:          chainCode,
		DerivationPath:     append([]uint32(nil), req.DerivationPath...),
		ECDSAPreparamsBlob: s.ecdsaPreparams,
	}
	switch resolved.Protocol {
	case mpcore.ProtocolECDSA:
		cfg.ECDSAShareBlob = shareBlob
	case mpcore.ProtocolEdDSA:
		cfg.EdDSAShareBlob = shareBlob
	default:
		return nil, fmt.Errorf("unsupported protocol %s", resolved.Session.Protocol)
	}
	result, err := s.runSecureSession(ctx, resolved, cfg)
	if err != nil {
		return nil, err
	}
	if result == nil || result.Signature == nil {
		return nil, fmt.Errorf("sign completed without signature")
	}
	return &SignResult{
		SessionID:         resolved.Session.SessionID,
		WalletID:          resolved.Session.WalletID,
		KeyID:             resolved.Session.KeyID,
		Protocol:          resolved.Session.Protocol,
		Signature:         append([]byte(nil), result.Signature.Signature...),
		SignatureRecovery: append([]byte(nil), result.Signature.SignatureRecovery...),
		R:                 append([]byte(nil), result.Signature.R...),
		S:                 append([]byte(nil), result.Signature.S...),
		ResultType:        event.ResultTypeSuccess,
	}, nil
}

type resolvedSession struct {
	Session        SessionContext
	Protocol       mpcore.Protocol
	LocalIndex     uint16
	Participants   []mpcore.Participant
	PeerIdentities map[uint16]secure.PeerIdentity
}

func (s *Service) resolveSession(session SessionContext) (*resolvedSession, error) {
	if strings.TrimSpace(session.SessionID) == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(session.WalletID) == "" {
		return nil, fmt.Errorf("wallet_id is required")
	}
	if strings.TrimSpace(session.KeyID) == "" {
		session.KeyID = session.WalletID
	}
	if strings.TrimSpace(session.LocalParticipantID) == "" {
		return nil, fmt.Errorf("local_participant_id is required")
	}
	if session.LocalParticipantID != s.cfg.Runtime.ParticipantID {
		return nil, fmt.Errorf("request local_participant_id %q does not match runtime participant_id %q", session.LocalParticipantID, s.cfg.Runtime.ParticipantID)
	}
	protocol, err := parseProtocol(session.Protocol)
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
	return &resolvedSession{
		Session:        session,
		Protocol:       protocol,
		LocalIndex:     uint16(localIndex),
		Participants:   participants,
		PeerIdentities: peerIdentities,
	}, nil
}

func parseProtocol(value string) (mpcore.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ecdsa":
		return mpcore.ProtocolECDSA, nil
	case "eddsa":
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

func derivePublicKey(protocol string, shareBlob, preparams []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ecdsa":
		var pre ecdsakeygen.LocalPreParams
		if err := json.Unmarshal(preparams, &pre); err != nil {
			return nil, err
		}
		var share ecdsakeygen.LocalPartySaveData
		if err := json.Unmarshal(shareBlob, &share); err != nil {
			return nil, err
		}
		share.LocalPreParams = pre
		publicKey := share.ECDSAPub
		pubKey := &ecdsa.PublicKey{
			Curve: publicKey.Curve(),
			X:     publicKey.X(),
			Y:     publicKey.Y(),
		}
		return encoding.EncodeS256PubKey(pubKey)
	case "eddsa":
		var share eddsakeygen.LocalPartySaveData
		if err := json.Unmarshal(shareBlob, &share); err != nil {
			return nil, err
		}
		publicKey := share.EDDSAPub
		pk := edwards.PublicKey{
			Curve: publicKey.Curve(),
			X:     publicKey.X(),
			Y:     publicKey.Y(),
		}
		return pk.SerializeCompressed(), nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
}

func (s *Service) runSecureSession(ctx context.Context, session *resolvedSession, cfg mpcore.SessionConfig) (*mpcore.Result, error) {
	runner, err := newSessionRunner(session, cfg, s.natsConn, s.identityStore, s.cfg)
	if err != nil {
		return nil, err
	}
	return runner.Run(ctx)
}

func connectNATS(cfg NATSConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
	}
	if cfg.Username != "" || cfg.Password != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	return nats.Connect(cfg.URL, opts...)
}

type identityStore struct {
	inner *sdkstore.FileStore
}

func (s *identityStore) LoadIdentity(ref string) (secure.IdentityKeyPair, bool, error) {
	blob, err := s.inner.Load(ref + ".json")
	if err != nil {
		return secure.IdentityKeyPair{}, false, nil
	}
	var pair secure.IdentityKeyPair
	if err := json.Unmarshal(blob, &pair); err != nil {
		return secure.IdentityKeyPair{}, false, err
	}
	return pair, true, nil
}

func (s *identityStore) SaveIdentity(ref string, key secure.IdentityKeyPair) error {
	blob, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return s.inner.Save(ref+".json", blob)
}

type sessionRunner struct {
	resolved          *resolvedSession
	cfg               mpcore.SessionConfig
	natsConn          *nats.Conn
	session           *secure.SecureSession
	sub               *nats.Subscription
	readyPeers        map[string]struct{}
	peerReadyTimeout  time.Duration
	peerReadyInterval time.Duration
	pending           []envelope
	started           bool
}

type envelopeKind string

const (
	envelopeKindReady  envelopeKind = "ready"
	envelopeKindSecure envelopeKind = "secure"
)

type envelope struct {
	SessionID string          `json:"session_id"`
	WalletID  string          `json:"wallet_id"`
	Protocol  string          `json:"protocol"`
	Operation string          `json:"operation"`
	SenderID  string          `json:"sender_id"`
	Kind      envelopeKind    `json:"kind"`
	Message   *secure.Message `json:"message,omitempty"`
	SentAt    string          `json:"sent_at"`
}

func newSessionRunner(resolved *resolvedSession, cfg mpcore.SessionConfig, nc *nats.Conn, store secure.IdentityStore, appCfg Config) (*sessionRunner, error) {
	session, err := secure.NewSession(secure.SecureSessionConfig{
		Session:        cfg,
		IdentityStore:  store,
		IdentityRef:    identityRef(appCfg),
		PeerIdentities: resolved.PeerIdentities,
	})
	if err != nil {
		return nil, err
	}
	return &sessionRunner{
		resolved:          resolved,
		cfg:               cfg,
		natsConn:          nc,
		session:           session,
		readyPeers:        map[string]struct{}{},
		peerReadyTimeout:  parseDurationOrDefault(appCfg.Runtime.PeerReadyTimeout, 10*time.Second),
		peerReadyInterval: parseDurationOrDefault(appCfg.Runtime.PeerReadyInterval, 300*time.Millisecond),
	}, nil
}

func (r *sessionRunner) Run(ctx context.Context) (*mpcore.Result, error) {
	inboundSubject := relay.InboundNATSSubject(
		r.resolved.Session.LocalParticipantID,
		r.resolved.Session.WalletID,
		r.cfg.Operation.String(),
		r.cfg.SessionID,
		relayTail,
	)
	msgCh := make(chan *nats.Msg, 256)
	sub, err := r.natsConn.ChanSubscribe(inboundSubject, msgCh)
	if err != nil {
		return nil, err
	}
	r.sub = sub
	defer func() { _ = r.sub.Unsubscribe() }()
	if err := r.natsConn.Flush(); err != nil {
		return nil, err
	}

	if err := r.waitForPeersReady(ctx, msgCh); err != nil {
		return nil, err
	}
	outbound, result, err := r.session.Start()
	if err != nil {
		return nil, err
	}
	r.started = true
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
		case msg := <-msgCh:
			if msg == nil {
				continue
			}
			res, err := r.applyEnvelope(msg)
			if err != nil {
				return nil, err
			}
			if res != nil {
				return res, nil
			}
		}
	}
}

func (r *sessionRunner) waitForPeersReady(ctx context.Context, msgCh <-chan *nats.Msg) error {
	peers := r.peerIDsExceptSelf()
	if len(peers) == 0 {
		return nil
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, r.peerReadyTimeout)
	defer cancel()

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
			return fmt.Errorf("timeout waiting for peer readiness: %w", deadlineCtx.Err())
		case <-ticker.C:
		case msg := <-msgCh:
			if msg == nil {
				continue
			}
			if _, err := r.applyEnvelope(msg); err != nil {
				return err
			}
		}
	}
}

func (r *sessionRunner) publishReady(peers []string) error {
	for _, peerID := range peers {
		env := envelope{
			SessionID: r.cfg.SessionID,
			WalletID:  r.resolved.Session.WalletID,
			Protocol:  r.cfg.Protocol.String(),
			Operation: r.cfg.Operation.String(),
			SenderID:  r.resolved.Session.LocalParticipantID,
			Kind:      envelopeKindReady,
			SentAt:    time.Now().UTC().Format(time.RFC3339Nano),
		}
		if err := r.publishEnvelope(peerID, env); err != nil {
			return err
		}
	}
	return nil
}

func (r *sessionRunner) publishOutbound(messages []secure.Message) error {
	for _, message := range messages {
		recipients, err := r.recipientsForMessage(message)
		if err != nil {
			return err
		}
		for _, peerID := range recipients {
			cloned := cloneSecureMessage(message)
			env := envelope{
				SessionID: r.cfg.SessionID,
				WalletID:  r.resolved.Session.WalletID,
				Protocol:  r.cfg.Protocol.String(),
				Operation: r.cfg.Operation.String(),
				SenderID:  r.resolved.Session.LocalParticipantID,
				Kind:      envelopeKindSecure,
				Message:   cloned,
				SentAt:    time.Now().UTC().Format(time.RFC3339Nano),
			}
			if err := r.publishEnvelope(peerID, env); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *sessionRunner) publishEnvelope(peerID string, env envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	subject := relay.OutboundNATSSubject(peerID, r.resolved.Session.WalletID, r.cfg.Operation.String(), r.cfg.SessionID, relayTail)
	return r.natsConn.Publish(subject, payload)
}

func (r *sessionRunner) applyEnvelope(msg *nats.Msg) (*mpcore.Result, error) {
	var env envelope
	if err := json.Unmarshal(msg.Data, &env); err != nil {
		return nil, err
	}
	if env.SessionID != r.cfg.SessionID || env.WalletID != r.resolved.Session.WalletID {
		return nil, nil
	}
	return r.handleEnvelope(env)
}

func (r *sessionRunner) handleEnvelope(env envelope) (*mpcore.Result, error) {
	switch env.Kind {
	case envelopeKindReady:
		r.readyPeers[env.SenderID] = struct{}{}
		return nil, nil
	case envelopeKindSecure:
		if !r.started {
			r.pending = append(r.pending, env)
			return nil, nil
		}
		if env.Message == nil {
			return nil, nil
		}
		outbound, result, err := r.session.Apply(*env.Message)
		if err != nil {
			return nil, err
		}
		if err := r.publishOutbound(outbound); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, nil
	}
}

func (r *sessionRunner) recipientsForMessage(message secure.Message) ([]string, error) {
	switch message.Type {
	case secure.MessageTypeSignedBroadcast:
		return r.peerIDsExceptSelf(), nil
	case secure.MessageTypeEncryptedDirect:
		if message.EncryptedDirect == nil || len(message.EncryptedDirect.Message.RecipientIndexes) != 1 {
			return nil, fmt.Errorf("encrypted direct message must have exactly one recipient")
		}
		index := message.EncryptedDirect.Message.RecipientIndexes[0]
		if int(index) >= len(r.resolved.Participants) {
			return nil, fmt.Errorf("recipient index %d out of range", index)
		}
		recipientID := r.resolved.Participants[index].ID
		if recipientID == r.resolved.Session.LocalParticipantID {
			return nil, nil
		}
		return []string{recipientID}, nil
	default:
		return nil, fmt.Errorf("unsupported secure message type %q", message.Type)
	}
}

func (r *sessionRunner) peerIDsExceptSelf() []string {
	peers := make([]string, 0, len(r.resolved.Participants))
	for _, participant := range r.resolved.Participants {
		if participant.ID != r.resolved.Session.LocalParticipantID {
			peers = append(peers, participant.ID)
		}
	}
	return peers
}

func (r *sessionRunner) hasAllReadyPeers(peers []string) bool {
	for _, peerID := range peers {
		if _, ok := r.readyPeers[peerID]; !ok {
			return false
		}
	}
	return true
}

func identityRef(cfg Config) string {
	if cfg.Runtime.IdentityRef != "" {
		return cfg.Runtime.IdentityRef
	}
	return cfg.Runtime.ParticipantID
}

func parseDurationOrDefault(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
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

func ensureECDSAPreparams(cfg Config) ([]byte, error) {
	path := strings.TrimSpace(cfg.Runtime.ECDSAPreparamsPath)
	if path == "" {
		path = filepath.Join(cfg.Storage.RootDir, "runtime", "ecdsa_preparams.json")
	}
	if blob, err := os.ReadFile(path); err == nil {
		return blob, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	logger.Info("ECDSA preparams not found; generating new preparams", "path", path, "participant_id", cfg.Runtime.ParticipantID)
	params, err := ecdsakeygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, err
	}
	logger.Info("ECDSA preparams generated and saved", "path", path, "participant_id", cfg.Runtime.ParticipantID)
	return blob, nil
}
