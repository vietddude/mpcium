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

func TestRuntimeConsumesSharedRequestsAndPublishesResults(t *testing.T) {
	ns := startJetStreamTestServer(t)

	aliceCfg := Config{
		Environment: "development",
		NATS: NATSConfig{
			URL: ns.ClientURL(),
		},
		Runtime: RuntimeConfig{
			ParticipantID:      "alice",
			IdentityStoreDir:   filepath.Join(t.TempDir(), "alice", "identity-store"),
			ECDSAPreparamsPath: fixturePath("node0_pre_params_0.json"),
			RequestTimeout:     "15s",
		},
		Storage: StorageConfig{
			RootDir: filepath.Join(t.TempDir(), "alice", "state"),
		},
	}
	bobCfg := Config{
		Environment: "development",
		NATS: NATSConfig{
			URL: ns.ClientURL(),
		},
		Runtime: RuntimeConfig{
			ParticipantID:      "bob",
			IdentityStoreDir:   filepath.Join(t.TempDir(), "bob", "identity-store"),
			ECDSAPreparamsPath: fixturePath("node1_pre_params_0.json"),
			RequestTimeout:     "15s",
		},
		Storage: StorageConfig{
			RootDir: filepath.Join(t.TempDir(), "bob", "state"),
		},
	}

	aliceRuntime, err := NewRuntime(context.Background(), aliceCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aliceRuntime.Close() })
	bobRuntime, err := NewRuntime(context.Background(), bobCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bobRuntime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = aliceRuntime.Start(ctx)
	}()
	go func() {
		_ = bobRuntime.Start(ctx)
	}()
	require.Eventually(t, func() bool {
		return aliceRuntime.keygenSub != nil &&
			aliceRuntime.signSub != nil &&
			bobRuntime.keygenSub != nil &&
			bobRuntime.signSub != nil
	}, 2*time.Second, 10*time.Millisecond)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	keygenResultSub, err := nc.SubscribeSync(KeygenResultSubject("client-1", "shared-keygen"))
	require.NoError(t, err)

	aliceKey, err := loadOrCreateRuntimeIdentity(aliceCfg)
	require.NoError(t, err)
	bobKey, err := loadOrCreateRuntimeIdentity(bobCfg)
	require.NoError(t, err)
	participants := []Participant{
		{
			ID:                   "alice",
			Moniker:              "alice",
			IdentityPublicKeyHex: hexString(aliceKey.PublicKey),
		},
		{
			ID:                   "bob",
			Moniker:              "bob",
			IdentityPublicKeyHex: hexString(bobKey.PublicKey),
		},
	}
	keygenReq := KeygenRequest{
		Session: SessionContext{
			SessionID:    "shared-keygen",
			WalletID:     "wallet-1",
			Protocol:     "ecdsa",
			Operation:    "keygen",
			Threshold:    1,
			Participants: participants,
		},
	}
	keygenPayload, err := json.Marshal(keygenReq)
	require.NoError(t, err)

	require.NoError(t, nc.PublishMsg(&nats.Msg{
		Subject: KeygenRequestSubject("alice", "wallet-1", "shared-keygen"),
		Data:    keygenPayload,
		Header:  nats.Header{event.ClientIDHeader: []string{"client-1"}},
	}))
	require.NoError(t, nc.PublishMsg(&nats.Msg{
		Subject: KeygenRequestSubject("bob", "wallet-1", "shared-keygen"),
		Data:    keygenPayload,
		Header:  nats.Header{event.ClientIDHeader: []string{"client-1"}},
	}))

	keygenMsg, err := keygenResultSub.NextMsg(20 * time.Second)
	require.NoError(t, err)

	var keygenResult KeygenResult
	require.NoError(t, json.Unmarshal(keygenMsg.Data, &keygenResult))
	assert.Equalf(t, event.ResultTypeSuccess, keygenResult.ResultType, "keygen error: %s", keygenResult.ErrorReason)
	assert.NotEmpty(t, keygenResult.ShareRef)
	assert.NotEmpty(t, keygenResult.PubKey)
	require.Eventually(t, func() bool {
		_, _, err := aliceRuntime.service.store.LoadShare("ecdsa", "wallet-1")
		if err != nil {
			return false
		}
		_, _, err = bobRuntime.service.store.LoadShare("ecdsa", "wallet-1")
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)

	signResultSub, err := nc.SubscribeSync(SignResultSubject("client-1", "shared-sign"))
	require.NoError(t, err)

	signReq := SignRequest{
		Session: SessionContext{
			SessionID:    "shared-sign",
			WalletID:     "wallet-1",
			Protocol:     "ecdsa",
			Operation:    "sign",
			Threshold:    1,
			Participants: participants,
		},
		SignerIndexes:    []uint16{0, 1},
		MessageDigestHex: strings.Repeat("01", 32),
	}
	signPayload, err := json.Marshal(signReq)
	require.NoError(t, err)

	require.NoError(t, nc.PublishMsg(&nats.Msg{
		Subject: SignRequestSubject("alice", "wallet-1", "shared-sign"),
		Data:    signPayload,
		Header:  nats.Header{event.ClientIDHeader: []string{"client-1"}},
	}))
	require.NoError(t, nc.PublishMsg(&nats.Msg{
		Subject: SignRequestSubject("bob", "wallet-1", "shared-sign"),
		Data:    signPayload,
		Header:  nats.Header{event.ClientIDHeader: []string{"client-1"}},
	}))

	signMsg, err := signResultSub.NextMsg(20 * time.Second)
	require.NoError(t, err)

	var signResult SignResult
	require.NoError(t, json.Unmarshal(signMsg.Data, &signResult))
	assert.Equalf(t, event.ResultTypeSuccess, signResult.ResultType, "sign error: %s", signResult.ErrorReason)
	assert.NotEmpty(t, signResult.Signature)
}

func loadOrCreateRuntimeIdentity(cfg Config) (securecrypto.IdentityKeyPair, error) {
	store := &identityStore{
		inner: sdkstore.NewFileStore(filepath.Join(cfg.Runtime.IdentityStoreDir, "identity")),
	}
	return securecrypto.LoadOrCreateIdentity(store, identityRef(cfg), rand.Reader)
}
