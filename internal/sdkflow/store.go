package sdkflow

import (
	"fmt"
	"path/filepath"
	"strings"

	sdkstore "github.com/fystack/mpcium-sdk/store"
)

type Store struct {
	blobStore *sdkstore.FileStore
}

func NewStore(root string) *Store {
	return &Store{
		blobStore: sdkstore.NewFileStore(root),
	}
}

func (s *Store) SaveShare(protocol, walletID string, blob []byte) (string, error) {
	ref, err := shareRef(protocol, walletID)
	if err != nil {
		return "", err
	}
	return ref, s.blobStore.Save(ref, blob)
}

func (s *Store) LoadShare(protocol, walletID string) ([]byte, string, error) {
	ref, err := shareRef(protocol, walletID)
	if err != nil {
		return nil, "", err
	}
	blob, err := s.blobStore.Load(ref)
	if err != nil {
		return nil, "", err
	}
	return blob, ref, nil
}

func shareRef(protocol, walletID string) (string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	walletID = strings.TrimSpace(walletID)
	if protocol == "" {
		return "", fmt.Errorf("protocol is required")
	}
	if walletID == "" {
		return "", fmt.Errorf("wallet_id is required")
	}
	return filepath.ToSlash(filepath.Join("shares", protocol, walletID+".json")), nil
}
