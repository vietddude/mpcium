package sdkflow

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fystack/mpcium-sdk/securecrypto"
	sdkstore "github.com/fystack/mpcium-sdk/store"
)

func TestStoreSaveLoadShare(t *testing.T) {
	store := NewStore(t.TempDir())

	ref, err := store.SaveShare("ecdsa", "wallet-1", []byte("share"))
	require.NoError(t, err)
	assert.Equal(t, filepath.ToSlash(filepath.Join("shares", "ecdsa", "wallet-1.json")), ref)

	blob, gotRef, err := store.LoadShare("ecdsa", "wallet-1")
	require.NoError(t, err)
	assert.Equal(t, ref, gotRef)
	assert.Equal(t, []byte("share"), blob)
}

func TestStoreSaveShareRequiresWalletID(t *testing.T) {
	store := NewStore(t.TempDir())

	_, err := store.SaveShare("ecdsa", "", []byte("share"))
	require.Error(t, err)
	assert.Equal(t, "wallet_id is required", err.Error())
}

func TestResolveSessionRequiresSessionID(t *testing.T) {
	service := testServiceForResolve(t, "node-a")

	_, err := service.resolveSession(SessionContext{
		WalletID:           "wallet-1",
		Protocol:           "ecdsa",
		LocalParticipantID: "node-a",
		Threshold:          0,
		Participants: []Participant{
			{ID: "node-a", IdentityPublicKeyHex: strings.Repeat("11", 32)},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session_id is required")
}

func TestResolveSessionBuildsParticipants(t *testing.T) {
	service := testServiceForResolve(t, "node-a")

	resolved, err := service.resolveSession(SessionContext{
		SessionID:          "session-1",
		WalletID:           "wallet-1",
		Protocol:           "ecdsa",
		LocalParticipantID: "node-a",
		Threshold:          1,
		Participants: []Participant{
			{
				ID:                   "node-a",
				Moniker:              "Node A",
				UniqueKeyHex:         "6e6f64652d61",
				IdentityPublicKeyHex: strings.Repeat("11", 32),
			},
			{
				ID:                   "node-b",
				Moniker:              "Node B",
				UniqueKeyHex:         "6e6f64652d62",
				IdentityPublicKeyHex: strings.Repeat("22", 32),
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, uint16(0), resolved.LocalIndex)
	assert.Len(t, resolved.Participants, 2)
	assert.Equal(t, "node-a", resolved.Participants[0].ID)
	assert.Equal(t, "Node B", resolved.Participants[1].Moniker)
	require.Contains(t, resolved.PeerIdentities, uint16(1))
	assert.Len(t, resolved.PeerIdentities[1].PublicKey, 32)
}

func TestEnsureECDSAPreparamsGeneratesWhenMissing(t *testing.T) {
	cfg := Config{
		Runtime: RuntimeConfig{
			ParticipantID: "node-a",
		},
		Storage: StorageConfig{
			RootDir: t.TempDir(),
		},
	}

	blob, err := ensureECDSAPreparams(cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, blob)

	path := filepath.Join(cfg.Storage.RootDir, "runtime", "ecdsa_preparams.json")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
}

func TestServiceKeygenAndSignAcrossTwoParticipants(t *testing.T) {
	ns := startJetStreamTestServer(t)

	bridgeConn, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(bridgeConn.Close)
	stopBridge := startRelayLoopback(t, bridgeConn)
	t.Cleanup(stopBridge)

	alice := newTestService(t, ns.ClientURL(), "alice", fixturePath("node0_pre_params_0.json"))
	bob := newTestService(t, ns.ClientURL(), "bob", fixturePath("node1_pre_params_0.json"))
	t.Cleanup(func() { _ = alice.Close() })
	t.Cleanup(func() { _ = bob.Close() })

	participants := buildParticipantsFromServices(t, alice, bob)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	keygenReqs := []KeygenRequest{
		{Session: SessionContext{
			SessionID:          "keygen-session-1",
			WalletID:           "wallet-1",
			Protocol:           "ecdsa",
			Operation:          "keygen",
			LocalParticipantID: "alice",
			Threshold:          1,
			Participants:       participants,
		}},
		{Session: SessionContext{
			SessionID:          "keygen-session-1",
			WalletID:           "wallet-1",
			Protocol:           "ecdsa",
			Operation:          "keygen",
			LocalParticipantID: "bob",
			Threshold:          1,
			Participants:       participants,
		}},
	}

	runConcurrent(
		t,
		func() error { _, err := alice.RunKeygen(ctx, keygenReqs[0]); return err },
		func() error { _, err := bob.RunKeygen(ctx, keygenReqs[1]); return err },
	)

	aliceShare, _, err := alice.store.LoadShare("ecdsa", "wallet-1")
	require.NoError(t, err)
	bobShare, _, err := bob.store.LoadShare("ecdsa", "wallet-1")
	require.NoError(t, err)
	assert.NotEmpty(t, aliceShare)
	assert.NotEmpty(t, bobShare)

	signReqAlice := SignRequest{
		Session: SessionContext{
			SessionID:          "sign-session-1",
			WalletID:           "wallet-1",
			Protocol:           "ecdsa",
			Operation:          "sign",
			LocalParticipantID: "alice",
			Threshold:          1,
			Participants:       participants,
		},
		SignerIndexes:    []uint16{0, 1},
		MessageDigestHex: strings.Repeat("01", 32),
	}
	signReqBob := signReqAlice
	signReqBob.Session.LocalParticipantID = "bob"

	var aliceResult *SignResult
	var bobResult *SignResult
	runConcurrent(t,
		func() error {
			var err error
			aliceResult, err = alice.RunSign(ctx, signReqAlice)
			return err
		},
		func() error {
			var err error
			bobResult, err = bob.RunSign(ctx, signReqBob)
			return err
		},
	)
	require.NotNil(t, aliceResult)
	require.NotNil(t, bobResult)
	assert.NotEmpty(t, aliceResult.Signature)
	assert.NotEmpty(t, bobResult.Signature)
	assert.Equal(t, aliceResult.Signature, bobResult.Signature)
}

func testServiceForResolve(t *testing.T, participantID string) *Service {
	t.Helper()
	return &Service{
		cfg: Config{
			Runtime: RuntimeConfig{
				ParticipantID: participantID,
			},
		},
	}
}

func newTestService(t *testing.T, natsURL, participantID, preparamsPath string) *Service {
	t.Helper()
	cfg := Config{
		Environment: "development",
		NATS: NATSConfig{
			URL: natsURL,
		},
		Runtime: RuntimeConfig{
			ParticipantID:      participantID,
			IdentityStoreDir:   filepath.Join(t.TempDir(), participantID, "identity-store"),
			ECDSAPreparamsPath: preparamsPath,
			PeerReadyTimeout:   "8s",
			PeerReadyInterval:  "100ms",
		},
		Storage: StorageConfig{
			RootDir: filepath.Join(t.TempDir(), participantID, "state"),
		},
	}
	service, err := NewService(cfg)
	require.NoError(t, err)
	return service
}

func buildParticipantsFromServices(t *testing.T, services ...*Service) []Participant {
	t.Helper()
	participants := make([]Participant, 0, len(services))
	for _, service := range services {
		store := &identityStore{
			inner: sdkstore.NewFileStore(
				filepath.Join(service.cfg.Runtime.IdentityStoreDir, "identity"),
			),
		}
		key, err := securecrypto.LoadOrCreateIdentity(store, identityRef(service.cfg), rand.Reader)
		require.NoError(t, err)
		participants = append(participants, Participant{
			ID:                   service.cfg.Runtime.ParticipantID,
			Moniker:              service.cfg.Runtime.ParticipantID,
			UniqueKeyHex:         "",
			IdentityPublicKeyHex: strings.ToLower(hexString(key.PublicKey)),
		})
	}
	return participants
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "e2e", "fixtures", name)
}

func runConcurrent(t *testing.T, fns ...func() error) {
	t.Helper()
	var wg sync.WaitGroup
	errCh := make(chan error, len(fns))
	for _, fn := range fns {
		wg.Add(1)
		go func(fn func() error) {
			defer wg.Done()
			errCh <- fn()
		}(fn)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func startJetStreamTestServer(t *testing.T) *natsserver.Server {
	t.Helper()
	server, err := natsserver.NewServer(&natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		NoLog:     true,
		NoSigs:    true,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
	require.NoError(t, err)
	go server.Start()
	if !server.ReadyForConnections(3 * time.Second) {
		t.Skip("embedded NATS server is not available in this environment")
	}
	t.Cleanup(server.Shutdown)
	return server
}

func startRelayLoopback(t *testing.T, nc *nats.Conn) func() {
	t.Helper()
	sub, err := nc.Subscribe(relayOutboundPrefix()+".>", func(msg *nats.Msg) {
		subject := strings.Replace(msg.Subject, relayOutboundPrefix(), relayInboundPrefix(), 1)
		_ = nc.PublishMsg(&nats.Msg{
			Subject: subject,
			Data:    msg.Data,
			Header:  msg.Header,
		})
	})
	require.NoError(t, err)
	require.NoError(t, nc.Flush())
	return func() { _ = sub.Unsubscribe() }
}

func relayOutboundPrefix() string { return "mpc.relay.to_cosigner" }

func relayInboundPrefix() string { return "mpc.relay.from_cosigner" }

func hexString(blob []byte) string {
	const hextable = "0123456789abcdef"
	out := make([]byte, len(blob)*2)
	for i, b := range blob {
		out[i*2] = hextable[b>>4]
		out[i*2+1] = hextable[b&0x0f]
	}
	return string(out)
}
