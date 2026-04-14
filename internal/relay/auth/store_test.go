package auth

import (
	"context"
	"testing"

	"github.com/fystack/mpcium/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticStoreAuthenticate(t *testing.T) {
	store, err := NewStaticStore([]config.RelayCosignerCredential{
		{
			CosignerID: "cosigner-1",
			Username:   "user-1",
			Password:   "secret-1",
		},
	})
	require.NoError(t, err)

	cosignerID, err := store.Authenticate(context.Background(), "user-1", "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "cosigner-1", cosignerID)

	_, err = store.Authenticate(context.Background(), "user-1", "wrong")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestStaticStoreRejectsDuplicateUsername(t *testing.T) {
	_, err := NewStaticStore([]config.RelayCosignerCredential{
		{
			CosignerID: "cosigner-1",
			Username:   "shared",
			Password:   "secret-1",
		},
		{
			CosignerID: "cosigner-2",
			Username:   "shared",
			Password:   "secret-2",
		},
	})
	require.ErrorIs(t, err, ErrDuplicateUsername)
}
