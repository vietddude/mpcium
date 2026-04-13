package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fystack/mpcium-sdk/secure"
	"github.com/fystack/mpcium/pkg/identity"
)

type LegacyIdentityStore struct {
	rootPath   string
	passphrase string
}

func NewLegacyIdentityStore(path string, passphrase string) (*LegacyIdentityStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("identity store path is required")
	}
	if strings.TrimSpace(passphrase) == "" {
		return nil, errors.New("age passphrase is required")
	}
	return &LegacyIdentityStore{
		rootPath:   filepath.Clean(path),
		passphrase: passphrase,
	}, nil
}

func (s *LegacyIdentityStore) LoadIdentity(ref string) (secure.IdentityKeyPair, bool, error) {
	key, err := identity.LoadSecureIdentityKeyPair(s.rootPath, ref, true, s.passphraseFilePath(ref))
	if err == nil {
		return key, true, nil
	}
	if key, err = identity.LoadSecureIdentityKeyPair(s.rootPath, ref, false, ""); err == nil {
		return key, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return secure.IdentityKeyPair{}, false, nil
	}
	return secure.IdentityKeyPair{}, false, err
}

func (s *LegacyIdentityStore) SaveIdentity(ref string, key secure.IdentityKeyPair) error {
	if strings.TrimSpace(ref) == "" {
		return errors.New("identity ref is required")
	}
	if err := os.MkdirAll(s.rootPath, 0o750); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}
	record := identity.NodeIdentity{
		NodeName:  ref,
		NodeID:    ref,
		PublicKey: hex.EncodeToString(key.PublicKey),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity record for %q: %w", ref, err)
	}
	if err := os.WriteFile(s.identityFilePath(ref), data, 0o600); err != nil {
		return fmt.Errorf("write identity file for %q: %w", ref, err)
	}
	if err := os.WriteFile(s.privateKeyPath(ref), []byte(hex.EncodeToString(key.PrivateKey)), 0o600); err != nil {
		return fmt.Errorf("write private key for %q: %w", ref, err)
	}
	return os.WriteFile(s.passphraseFilePath(ref), []byte(s.passphrase+"\n"), 0o600)
}

func (s *LegacyIdentityStore) Close() error {
	return nil
}

func (s *LegacyIdentityStore) identityFilePath(ref string) string {
	return filepath.Join(s.rootPath, fmt.Sprintf("%s_identity.json", ref))
}

func (s *LegacyIdentityStore) privateKeyPath(ref string) string {
	return filepath.Join(s.rootPath, fmt.Sprintf("%s_private.key", ref))
}

func (s *LegacyIdentityStore) passphraseFilePath(ref string) string {
	return filepath.Join(s.rootPath, fmt.Sprintf("%s_private.passphrase", ref))
}
