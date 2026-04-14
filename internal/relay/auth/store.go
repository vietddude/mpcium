package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/fystack/mpcium/pkg/config"
)

var (
	ErrInvalidCredentials = errors.New("invalid cosigner credentials")
	ErrDuplicateUsername  = errors.New("duplicate cosigner username")
	ErrInvalidCredential  = errors.New("cosigner credential is incomplete")
)

type Store interface {
	Authenticate(ctx context.Context, username, password string) (cosignerID string, err error)
}

type credentialRecord struct {
	cosignerID string
	password   string
}

type staticStore struct {
	byUsername map[string]credentialRecord
}

func NewStaticStore(credentials []config.RelayCosignerCredential) (Store, error) {
	byUsername := make(map[string]credentialRecord, len(credentials))

	for _, c := range credentials {
		if err := validateCredential(c); err != nil {
			return nil, err
		}
		if _, exists := byUsername[c.Username]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateUsername, c.Username)
		}
		byUsername[c.Username] = credentialRecord{
			cosignerID: c.CosignerID,
			password:   c.Password,
		}
	}

	return &staticStore{byUsername: byUsername}, nil
}

func (s *staticStore) Authenticate(_ context.Context, username, password string) (string, error) {
	record, ok := s.byUsername[username]
	if !ok || !constantTimeEqual(record.password, password) {
		return "", ErrInvalidCredentials
	}
	return record.cosignerID, nil
}

func validateCredential(c config.RelayCosignerCredential) error {
	if strings.TrimSpace(c.CosignerID) == "" || c.Username == "" || c.Password == "" {
		return fmt.Errorf("%w: cosigner_id, username, and password are required", ErrInvalidCredential)
	}
	return nil
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
