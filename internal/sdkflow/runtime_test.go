package sdkflow

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fystack/mpcium-sdk/securecrypto"
	sdkstore "github.com/fystack/mpcium-sdk/store"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConsumesTargetedRequestsAndPublishesResults(t *testing.T) {
	ns := startJetStreamTestServer(t)

	cfg := Config{
		Environment: "development",
		NATS: NATSConfig{
			URL: ns.ClientURL(),
		},
		Runtime: RuntimeConfig{
			ParticipantID:      "solo",
			IdentityStoreDir:   filepath.Join(t.TempDir(), "solo", "identity-store"),
			ECDSAPreparamsPath: fixturePath("node0_pre_params_0.json"),
			RequestTimeout:     "15s",
		},
		Storage: StorageConfig{
			RootDir: filepath.Join(t.TempDir(), "solo", "state"),
		},
	}

	runtime, err := NewRuntime(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = runtime.Start(ctx)
	}()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	keygenResultSub, err := nc.SubscribeSync(KeygenResultSubject("client-1", "single-keygen"))
	require.NoError(t, err)

	key, err := loadOrCreateRuntimeIdentity(cfg)
	require.NoError(t, err)
	participants := []Participant{
		{
			ID:                   "solo",
			Moniker:              "solo",
			IdentityPublicKeyHex: hexString(key.PublicKey),
		},
	}
	keygenReq := KeygenRequest{
		Session: SessionContext{
			SessionID:          "single-keygen",
			WalletID:           "wallet-1",
			KeyID:              "wallet-1",
			Protocol:           "ecdsa",
			Operation:          "keygen",
			LocalParticipantID: "solo",
			Threshold:          0,
			Participants:       participants,
		},
	}
	keygenPayload, err := json.Marshal(keygenReq)
	require.NoError(t, err)

	require.NoError(t, nc.PublishMsg(&nats.Msg{
		Subject: KeygenRequestSubject("solo"),
		Data:    keygenPayload,
		Header:  nats.Header{event.ClientIDHeader: []string{"client-1"}},
	}))

	keygenMsg, err := keygenResultSub.NextMsg(20 * time.Second)
	require.NoError(t, err)

	var keygenResult KeygenResult
	require.NoError(t, json.Unmarshal(keygenMsg.Data, &keygenResult))
	assert.Equal(t, event.ResultTypeSuccess, keygenResult.ResultType)
	assert.NotEmpty(t, keygenResult.ShareRef)
	assert.NotEmpty(t, keygenResult.PubKey)

	signResultSub, err := nc.SubscribeSync(SignResultSubject("client-1", "single-sign"))
	require.NoError(t, err)

	signReq := SignRequest{
		Session: SessionContext{
			SessionID:          "single-sign",
			WalletID:           "wallet-1",
			KeyID:              "wallet-1",
			Protocol:           "ecdsa",
			Operation:          "sign",
			LocalParticipantID: "solo",
			Threshold:          0,
			Participants:       participants,
		},
		SignerIndexes:    []uint16{0},
		MessageDigestHex: strings.Repeat("01", 32),
	}
	signPayload, err := json.Marshal(signReq)
	require.NoError(t, err)

	require.NoError(t, nc.PublishMsg(&nats.Msg{
		Subject: SignRequestSubject("solo"),
		Data:    signPayload,
		Header:  nats.Header{event.ClientIDHeader: []string{"client-1"}},
	}))

	signMsg, err := signResultSub.NextMsg(20 * time.Second)
	require.NoError(t, err)

	var signResult SignResult
	require.NoError(t, json.Unmarshal(signMsg.Data, &signResult))
	assert.Equal(t, event.ResultTypeSuccess, signResult.ResultType)
	assert.NotEmpty(t, signResult.Signature)
}

func loadOrCreateRuntimeIdentity(cfg Config) (securecrypto.IdentityKeyPair, error) {
	store := &identityStore{inner: sdkstore.NewFileStore(filepath.Join(cfg.Runtime.IdentityStoreDir, "identity"))}
	return securecrypto.LoadOrCreateIdentity(store, identityRef(cfg), rand.Reader)
}
