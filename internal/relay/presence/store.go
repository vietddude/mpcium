package presence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store interface {
	MarkOnline(ctx context.Context, cosignerID, clientID string, at time.Time) error
	MarkOffline(ctx context.Context, cosignerID string, at time.Time) error
	Touch(ctx context.Context, cosignerID string, at time.Time) error
}

type redisStore struct {
	client    *redis.Client
	keyPrefix string
	onlineTTL time.Duration
}

func NewStore(client *redis.Client, keyPrefix string, onlineTTL time.Duration) Store {
	return &redisStore{
		client:    client,
		keyPrefix: normalizeKeyPrefix(keyPrefix),
		onlineTTL: onlineTTL,
	}
}

func PresenceKey(keyPrefix, cosignerID string) string {
	return fmt.Sprintf("%s:%s:presence", normalizeKeyPrefix(keyPrefix), cosignerID)
}

func (s *redisStore) MarkOnline(ctx context.Context, cosignerID, clientID string, at time.Time) error {
	ts := rfc3339(at)
	fields := map[string]any{
		"online":       "1",
		"client_id":    clientID,
		"connected_at": ts,
		"last_seen_at": ts,
	}
	return s.setFields(ctx, cosignerID, fields, true)
}

func (s *redisStore) MarkOffline(ctx context.Context, cosignerID string, at time.Time) error {
	fields := map[string]any{
		"online":       "0",
		"last_seen_at": rfc3339(at),
	}
	return s.setFields(ctx, cosignerID, fields, false)
}

func (s *redisStore) Touch(ctx context.Context, cosignerID string, at time.Time) error {
	fields := map[string]any{
		"last_seen_at": rfc3339(at),
	}
	return s.setFields(ctx, cosignerID, fields, true)
}

func (s *redisStore) setFields(ctx context.Context, cosignerID string, fields map[string]any, keepTTL bool) error {
	key := PresenceKey(s.keyPrefix, cosignerID)

	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, key, fields)
	if keepTTL && s.onlineTTL > 0 {
		pipe.Expire(ctx, key, s.onlineTTL)
	} else if !keepTTL {
		pipe.Persist(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func normalizeKeyPrefix(keyPrefix string) string {
	prefix := strings.TrimSuffix(strings.TrimSpace(keyPrefix), ":")
	if prefix == "" {
		return "cosigner"
	}
	return prefix
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
