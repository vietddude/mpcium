package service

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
	"github.com/fystack/mpcium-sdk/securecrypto"
	rbconfig "github.com/fystack/mpcium/internal/relaybridge/config"
	rbsession "github.com/fystack/mpcium/internal/relaybridge/session"
	st "github.com/fystack/mpcium/internal/relaybridge/sessiontransport"
	rbstorage "github.com/fystack/mpcium/internal/relaybridge/storage"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
)

type Service struct {
	cfg            rbconfig.Config
	store          rbstorage.KeyShareStorage
	identityStore  secure.IdentityStore
	transport      st.Transport
	ecdsaPreparams []byte
}

func New(
	cfg rbconfig.Config,
	store rbstorage.KeyShareStorage,
	identityStore secure.IdentityStore,
	transport st.Transport,
) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("share store is required")
	}
	if identityStore == nil {
		return nil, fmt.Errorf("identity store is required")
	}
	if transport == nil {
		return nil, fmt.Errorf("session transport is required")
	}
	preparams, err := ensureECDSAPreparams(cfg)
	if err != nil {
		return nil, fmt.Errorf("prepare ecdsa preparams: %w", err)
	}
	service := &Service{
		cfg:            cfg,
		store:          store,
		identityStore:  identityStore,
		transport:      transport,
		ecdsaPreparams: append([]byte(nil), preparams...),
	}
	if err := service.logLocalIdentityPublicKey(); err != nil {
		return nil, fmt.Errorf("load local identity: %w", err)
	}
	return service, nil
}

func (s *Service) RunKeygen(ctx context.Context, req rbtypes.KeygenRequest) (*rbtypes.KeygenResult, error) {
	resolved, err := rbsession.ResolveContext(req.Session, s.cfg.Runtime.ParticipantID)
	if err != nil {
		return nil, err
	}
	keyID := strings.TrimSpace(resolved.Session.WalletID)
	if keyID == "" {
		return nil, fmt.Errorf("wallet_id is required for sdk key_id")
	}
	exists, err := s.store.HasKeyShare(
		resolved.Session.WalletID,
		string(req.Session.Protocol),
		s.cfg.Runtime.ParticipantID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"check existing key share for wallet_id %q participant_id %q: %w",
			resolved.Session.WalletID,
			s.cfg.Runtime.ParticipantID,
			err,
		)
	}
	if exists {
		return nil, fmt.Errorf(
			"key share already exists for wallet_id %q protocol %q participant_id %q",
			resolved.Session.WalletID,
			req.Session.Protocol,
			s.cfg.Runtime.ParticipantID,
		)
	}
	cfg := mpcore.SessionConfig{
		SessionID:          resolved.Session.SessionID,
		Protocol:           resolved.Protocol,
		Operation:          mpcore.OperationKeygen,
		Participants:       resolved.Participants,
		LocalIndex:         resolved.LocalIndex,
		Threshold:          resolved.Session.Threshold,
		WalletID:           keyID,
		ECDSAPreparamsBlob: s.ecdsaPreparams,
	}
	result, err := s.runSecureSession(ctx, resolved, cfg)
	if err != nil {
		return nil, fmt.Errorf(
			"run keygen secure session for wallet_id %q session_id %q: %w",
			resolved.Session.WalletID,
			resolved.Session.SessionID,
			err,
		)
	}
	if result == nil || len(result.ShareBlob) == 0 {
		return nil, fmt.Errorf("keygen completed without share")
	}
	record := rbstorage.KeyShareRecord{
		WalletID:   resolved.Session.WalletID,
		KeyType:    string(req.Session.Protocol),
		Protocol:   string(req.Session.Protocol),
		CosignerID: s.cfg.Runtime.ParticipantID,
		SessionID:  resolved.Session.SessionID,
		ShareBlob:  result.ShareBlob,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.store.SaveKeyShare(record); err != nil {
		return nil, err
	}
	pubKey, err := derivePublicKey(string(req.Session.Protocol), result.ShareBlob, s.ecdsaPreparams)
	if err != nil {
		return nil, err
	}
	return &rbtypes.KeygenResult{
		SessionID:  resolved.Session.SessionID,
		WalletID:   resolved.Session.WalletID,
		Protocol:   string(resolved.Session.Protocol),
		PubKey:     pubKey,
		ResultType: event.ResultTypeSuccess,
	}, nil
}

func (s *Service) RunSign(ctx context.Context, req rbtypes.SignRequest) (*rbtypes.SignResult, error) {
	resolved, err := rbsession.ResolveContext(req.Session, s.cfg.Runtime.ParticipantID)
	if err != nil {
		return nil, err
	}
	keyID := strings.TrimSpace(resolved.Session.WalletID)
	if keyID == "" {
		return nil, fmt.Errorf("wallet_id is required for sdk key_id")
	}
	record, err := s.store.LoadKeyShare(
		resolved.Session.WalletID,
		string(req.Session.Protocol),
		s.cfg.Runtime.ParticipantID,
	)
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
		WalletID:           keyID,
		SignerIndexes:      append([]uint16(nil), req.SignerIndexes...),
		MessageDigest:      messageDigest,
		ChainCode:          chainCode,
		DerivationPath:     append([]uint32(nil), req.DerivationPath...),
		ECDSAPreparamsBlob: s.ecdsaPreparams,
	}
	switch resolved.Protocol {
	case mpcore.ProtocolECDSA:
		cfg.ECDSAShareBlob = record.ShareBlob
	case mpcore.ProtocolEdDSA:
		cfg.EdDSAShareBlob = record.ShareBlob
	default:
		return nil, fmt.Errorf("unsupported protocol %s", resolved.Session.Protocol)
	}
	result, err := s.runSecureSession(ctx, resolved, cfg)
	if err != nil {
		return nil, fmt.Errorf(
			"run sign secure session for wallet_id %q session_id %q: %w",
			resolved.Session.WalletID,
			resolved.Session.SessionID,
			err,
		)
	}
	if result == nil || result.Signature == nil {
		return nil, fmt.Errorf("sign completed without signature")
	}
	return &rbtypes.SignResult{
		SessionID:         resolved.Session.SessionID,
		WalletID:          resolved.Session.WalletID,
		Protocol:          string(resolved.Session.Protocol),
		Signature:         append([]byte(nil), result.Signature.Signature...),
		SignatureRecovery: append([]byte(nil), result.Signature.SignatureRecovery...),
		R:                 append([]byte(nil), result.Signature.R...),
		S:                 append([]byte(nil), result.Signature.S...),
		ResultType:        event.ResultTypeSuccess,
	}, nil
}

func (s *Service) runSecureSession(
	ctx context.Context,
	resolved *rbsession.ResolvedSession,
	cfg mpcore.SessionConfig,
) (*mpcore.Result, error) {
	runner, err := rbsession.NewRunner(resolved, cfg, s.transport, s.identityStore, s.cfg)
	if err != nil {
		return nil, fmt.Errorf(
			"initialize secure session for operation %q wallet_id %q session_id %q: %w",
			cfg.Operation.String(),
			resolved.Session.WalletID,
			cfg.SessionID,
			err,
		)
	}
	result, err := runner.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"execute secure session for operation %q wallet_id %q session_id %q: %w",
			cfg.Operation.String(),
			resolved.Session.WalletID,
			cfg.SessionID,
			err,
		)
	}
	return result, nil
}

func (s *Service) Store() rbstorage.KeyShareStorage {
	return s.store
}

func (s *Service) IdentityStore() secure.IdentityStore {
	return s.identityStore
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

func (s *Service) logLocalIdentityPublicKey() error {
	key, err := securecrypto.LoadOrCreateIdentity(s.identityStore, s.cfg.IdentityRef(), nil)
	if err != nil {
		return err
	}
	logger.Info(
		"relaybridge flow local identity loaded",
		"participant_id",
		s.cfg.Runtime.ParticipantID,
		"identity_ref",
		s.cfg.IdentityRef(),
		"identity_public_key_hex",
		strings.ToLower(hex.EncodeToString(key.PublicKey)),
	)
	return nil
}

func ensureECDSAPreparams(cfg rbconfig.Config) ([]byte, error) {
	path := cfg.ECDSAPreparamsPath()
	if blob, err := os.ReadFile(path); err == nil {
		return blob, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	logger.Info(
		"ECDSA preparams not found; generating new preparams",
		"path",
		path,
		"participant_id",
		cfg.Runtime.ParticipantID,
	)
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
	logger.Info(
		"ECDSA preparams generated and saved",
		"path",
		path,
		"participant_id",
		cfg.Runtime.ParticipantID,
	)
	return blob, nil
}
