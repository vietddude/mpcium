package presence

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreLifecycle(t *testing.T) {
	mini, err := miniredis.Run()
	if err != nil {
		t.Skipf("embedded redis is not available in this environment: %v", err)
	}
	t.Cleanup(mini.Close)

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewStore(client, "cosigner", 30*time.Second)
	ctx := context.Background()
	at := time.Date(2026, 4, 9, 10, 0, 0, 0, time.UTC)

	require.NoError(t, store.MarkOnline(ctx, "cosigner-1", "mqtt-client-1", at))

	key := PresenceKey("cosigner", "cosigner-1")
	values, err := client.HGetAll(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", values["online"])
	assert.Equal(t, "mqtt-client-1", values["client_id"])
	assert.Equal(t, at.Format(time.RFC3339), values["connected_at"])
	assert.Equal(t, at.Format(time.RFC3339), values["last_seen_at"])
	assert.Equal(t, 30*time.Second, mini.TTL(key))

	touchedAt := at.Add(12 * time.Second)
	require.NoError(t, store.Touch(ctx, "cosigner-1", touchedAt))
	values, err = client.HGetAll(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, touchedAt.Format(time.RFC3339), values["last_seen_at"])
	assert.Equal(t, 30*time.Second, mini.TTL(key))

	offlineAt := at.Add(20 * time.Second)
	require.NoError(t, store.MarkOffline(ctx, "cosigner-1", offlineAt))
	values, err = client.HGetAll(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, "0", values["online"])
	assert.Equal(t, offlineAt.Format(time.RFC3339), values["last_seen_at"])
	assert.Equal(t, time.Duration(0), mini.TTL(key))
}
