package relay

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type PresenceStore interface {
	MarkOnline(ctx context.Context, cosignerID, clientID string, at time.Time) error
	MarkOffline(ctx context.Context, cosignerID string, at time.Time) error
	Touch(ctx context.Context, cosignerID string, at time.Time) error
}

type RedisPresenceStore struct {
	client    *redis.Client
	keyPrefix string
	onlineTTL time.Duration
}

func NewRedisPresenceStore(client *redis.Client, keyPrefix string, onlineTTL time.Duration) *RedisPresenceStore {
	prefix := strings.TrimSuffix(strings.TrimSpace(keyPrefix), ":")
	if prefix == "" {
		prefix = "cosigner"
	}

	return &RedisPresenceStore{
		client:    client,
		keyPrefix: prefix,
		onlineTTL: onlineTTL,
	}
}

func (s *RedisPresenceStore) MarkOnline(ctx context.Context, cosignerID, clientID string, at time.Time) error {
	key := s.key(cosignerID)
	values := map[string]any{
		"online":       "1",
		"client_id":    clientID,
		"connected_at": at.UTC().Format(time.RFC3339),
		"last_seen_at": at.UTC().Format(time.RFC3339),
	}

	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, key, values)
	if s.onlineTTL > 0 {
		pipe.Expire(ctx, key, s.onlineTTL)
	} else {
		pipe.Persist(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisPresenceStore) MarkOffline(ctx context.Context, cosignerID string, at time.Time) error {
	key := s.key(cosignerID)

	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		"online":       "0",
		"last_seen_at": at.UTC().Format(time.RFC3339),
	})
	pipe.Persist(ctx, key)

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisPresenceStore) Touch(ctx context.Context, cosignerID string, at time.Time) error {
	key := s.key(cosignerID)

	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		"last_seen_at": at.UTC().Format(time.RFC3339),
	})
	if s.onlineTTL > 0 {
		pipe.Expire(ctx, key, s.onlineTTL)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisPresenceStore) PresenceKey(cosignerID string) string {
	return s.key(cosignerID)
}

func (s *RedisPresenceStore) key(cosignerID string) string {
	return fmt.Sprintf("%s:%s:presence", s.keyPrefix, cosignerID)
}
