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

func (s *Store) SaveShare(protocol, keyID string, blob []byte) (string, error) {
	ref, err := shareRef(protocol, keyID)
	if err != nil {
		return "", err
	}
	return ref, s.blobStore.Save(ref, blob)
}

func (s *Store) LoadShare(protocol, keyID string) ([]byte, string, error) {
	ref, err := shareRef(protocol, keyID)
	if err != nil {
		return nil, "", err
	}
	blob, err := s.blobStore.Load(ref)
	if err != nil {
		return nil, "", err
	}
	return blob, ref, nil
}

func shareRef(protocol, keyID string) (string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	keyID = strings.TrimSpace(keyID)
	if protocol == "" {
		return "", fmt.Errorf("protocol is required")
	}
	if keyID == "" {
		return "", fmt.Errorf("key_id is required")
	}
	return filepath.ToSlash(filepath.Join("shares", protocol, keyID+".json")), nil
}
