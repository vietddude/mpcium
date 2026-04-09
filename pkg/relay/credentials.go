package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fystack/mpcium/pkg/config"
)

var (
	ErrInvalidCredentials = errors.New("invalid cosigner credentials")
	ErrDuplicateUsername  = errors.New("duplicate cosigner username")
	ErrInvalidCredential  = errors.New("invalid cosigner credential")
)

type CredentialStore interface {
	Authenticate(ctx context.Context, username, password string) (cosignerID string, err error)
}

type staticCredentialStore struct {
	byUsername map[string]config.RelayCosignerCredential
}

func NewStaticCredentialStore(credentials []config.RelayCosignerCredential) (CredentialStore, error) {
	store := &staticCredentialStore{
		byUsername: make(map[string]config.RelayCosignerCredential, len(credentials)),
	}

	for _, credential := range credentials {
		if strings.TrimSpace(credential.CosignerID) == "" || credential.Username == "" || credential.Password == "" {
			return nil, fmt.Errorf("%w: cosigner_id, username, and password are required", ErrInvalidCredential)
		}

		if _, exists := store.byUsername[credential.Username]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateUsername, credential.Username)
		}

		store.byUsername[credential.Username] = credential
	}

	return store, nil
}

func (s *staticCredentialStore) Authenticate(_ context.Context, username, password string) (string, error) {
	credential, ok := s.byUsername[username]
	if !ok || credential.Password != password {
		return "", ErrInvalidCredentials
	}

	return credential.CosignerID, nil
}
