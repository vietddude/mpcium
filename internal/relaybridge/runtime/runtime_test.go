package runtime

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/fystack/mpcium-sdk/securecrypto"
	rbconfig "github.com/fystack/mpcium/internal/relaybridge/config"
	routing "github.com/fystack/mpcium/internal/relaybridge/routing"
	rbstorage "github.com/fystack/mpcium/internal/relaybridge/storage"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAgePassphrase = "relaybridge-runtime-test-passphrase"

func TestRuntimeTwoInternalNodesKeygenAndSign(t *testing.T) {
	ns := startJetStreamTestServer(t)

	aliceCfg := testConfig(t, ns.ClientURL(), "alice", fixturePath("node0_pre_params_0.json"))
	bobCfg := testConfig(t, ns.ClientURL(), "bob", fixturePath("node1_pre_params_0.json"))

	aliceRuntime, err := New(context.Background(), aliceCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aliceRuntime.Close() })

	bobRuntime, err := New(context.Background(), bobCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bobRuntime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = aliceRuntime.Run(ctx) }()
	go func() { _ = bobRuntime.Run(ctx) }()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	participants := buildParticipants(t, aliceCfg, bobCfg)

	keygenReq := rbtypes.KeygenRequest{
		Session: rbtypes.SessionContext{
			SessionID:    "internal-keygen",
			WalletID:     "wallet-internal",
			Protocol:     rbtypes.ProtocolECDSA,
			Operation:    rbtypes.OperationKeygen,
			Threshold:    1,
			Participants: participants,
		},
	}
	keygenResult := waitForKeygenResult(t, nc, "client-1", keygenReq.Session.SessionID, func() {
		publishForParticipants(t, nc, participants, keygenReq.Session.WalletID, keygenReq.Session.SessionID, rbtypes.OperationKeygen, keygenReq, "client-1")
	})
	assert.Equalf(t, event.ResultTypeSuccess, keygenResult.ResultType, "keygen error: %s", keygenResult.ErrorReason)

	require.Eventually(t, func() bool {
		_, err := aliceRuntime.KeyShareStore().LoadKeyShare("wallet-internal", "ecdsa", "alice")
		if err != nil {
			return false
		}
		_, err = bobRuntime.KeyShareStore().LoadKeyShare("wallet-internal", "ecdsa", "bob")
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)

	signReq := rbtypes.SignRequest{
		Session: rbtypes.SessionContext{
			SessionID:    "internal-sign",
			WalletID:     "wallet-internal",
			Protocol:     rbtypes.ProtocolECDSA,
			Operation:    rbtypes.OperationSign,
			Threshold:    1,
			Participants: participants,
		},
		SignerIndexes:    []uint16{0, 1},
		MessageDigestHex: strings.Repeat("01", 32),
	}
	signResult := waitForSignResult(t, nc, "client-1", signReq.Session.SessionID, func() {
		publishForParticipants(t, nc, participants, signReq.Session.WalletID, signReq.Session.SessionID, rbtypes.OperationSign, signReq, "client-1")
	})
	assert.Equalf(t, event.ResultTypeSuccess, signResult.ResultType, "sign error: %s", signResult.ErrorReason)
	assert.NotEmpty(t, signResult.Signature)
}

func TestRuntimeInternalNodeAndRelayParticipantKeygenAndSign(t *testing.T) {
	ns := startJetStreamTestServer(t)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	stopBridge := startRelayLoopback(t, nc)
	t.Cleanup(stopBridge)

	nodeCfg := testConfig(t, ns.ClientURL(), "node0", fixturePath("node0_pre_params_0.json"))
	cosignerCfg := testConfig(t, ns.ClientURL(), "cosigner-1", fixturePath("node1_pre_params_0.json"))

	nodeRuntime, err := New(context.Background(), nodeCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeRuntime.Close() })

	cosignerRuntime, err := New(context.Background(), cosignerCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cosignerRuntime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = nodeRuntime.Run(ctx) }()
	go func() { _ = cosignerRuntime.Run(ctx) }()

	participants := []rbtypes.Participant{
		buildParticipant(t, nodeCfg, rbtypes.ParticipantNode),
		buildParticipant(t, cosignerCfg, rbtypes.ParticipantServer),
	}

	keygenReq := rbtypes.KeygenRequest{
		Session: rbtypes.SessionContext{
			SessionID:    "mixed-keygen",
			WalletID:     "wallet-mixed",
			Protocol:     rbtypes.ProtocolECDSA,
			Operation:    rbtypes.OperationKeygen,
			Threshold:    1,
			Participants: participants,
		},
	}
	keygenResult := waitForKeygenResult(t, nc, "client-2", keygenReq.Session.SessionID, func() {
		publishForParticipants(t, nc, participants, keygenReq.Session.WalletID, keygenReq.Session.SessionID, rbtypes.OperationKeygen, keygenReq, "client-2")
	})
	assert.Equalf(t, event.ResultTypeSuccess, keygenResult.ResultType, "keygen error: %s", keygenResult.ErrorReason)

	signReq := rbtypes.SignRequest{
		Session: rbtypes.SessionContext{
			SessionID:    "mixed-sign",
			WalletID:     "wallet-mixed",
			Protocol:     rbtypes.ProtocolECDSA,
			Operation:    rbtypes.OperationSign,
			Threshold:    1,
			Participants: participants,
		},
		SignerIndexes:    []uint16{0, 1},
		MessageDigestHex: strings.Repeat("02", 32),
	}
	signResult := waitForSignResult(t, nc, "client-2", signReq.Session.SessionID, func() {
		publishForParticipants(t, nc, participants, signReq.Session.WalletID, signReq.Session.SessionID, rbtypes.OperationSign, signReq, "client-2")
	})
	assert.Equalf(t, event.ResultTypeSuccess, signResult.ResultType, "sign error: %s", signResult.ErrorReason)
	assert.NotEmpty(t, signResult.Signature)
}

func TestRuntimeDuplicateKeygenDeliveryDoesNotSpawnDuplicateRunner(t *testing.T) {
	ns := startJetStreamTestServer(t)

	aliceCfg := testConfig(t, ns.ClientURL(), "alice", fixturePath("node0_pre_params_0.json"))
	bobCfg := testConfig(t, ns.ClientURL(), "bob", fixturePath("node1_pre_params_0.json"))

	aliceRuntime, err := New(context.Background(), aliceCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aliceRuntime.Close() })

	bobRuntime, err := New(context.Background(), bobCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bobRuntime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = aliceRuntime.Run(ctx) }()
	go func() { _ = bobRuntime.Run(ctx) }()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	participants := buildParticipants(t, aliceCfg, bobCfg)
	req := rbtypes.KeygenRequest{
		Session: rbtypes.SessionContext{
			SessionID:    "duplicate-keygen",
			WalletID:     "wallet-duplicate",
			Protocol:     rbtypes.ProtocolECDSA,
			Operation:    rbtypes.OperationKeygen,
			Threshold:    1,
			Participants: participants,
		},
	}

	sub, err := nc.SubscribeSync(routing.KeygenResultSubject("client-dup", req.Session.SessionID))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	publishForParticipants(t, nc, participants, req.Session.WalletID, req.Session.SessionID, rbtypes.OperationKeygen, req, "client-dup")
	publishForParticipants(t, nc, participants, req.Session.WalletID, req.Session.SessionID, rbtypes.OperationKeygen, req, "client-dup")

	msg, err := sub.NextMsg(20 * time.Second)
	require.NoError(t, err)
	var result rbtypes.KeygenResult
	require.NoError(t, json.Unmarshal(msg.Data, &result))
	assert.Equalf(t, event.ResultTypeSuccess, result.ResultType, "keygen error: %s", result.ErrorReason)

	_, err = sub.NextMsg(500 * time.Millisecond)
	require.ErrorIs(t, err, nats.ErrTimeout)
}

func testConfig(t *testing.T, natsURL, participantID, preparamsPath string) rbconfig.Config {
	t.Helper()
	return rbconfig.Config{
		Environment: "development",
		NATS: rbconfig.NATSConfig{
			URL: natsURL,
		},
		Runtime: rbconfig.RuntimeConfig{
			ParticipantID:      participantID,
			IdentityStoreDir:   filepath.Join(t.TempDir(), participantID, "identity-store"),
			ECDSAPreparamsPath: preparamsPath,
			PeerReadyTimeout:   "8s",
			PeerReadyInterval:  "100ms",
			RequestTimeout:     "15s",
		},
		Storage: rbconfig.StorageConfig{
			RootDir:       filepath.Join(t.TempDir(), participantID, "state"),
			AgePassphrase: testAgePassphrase,
		},
	}
}

func buildParticipants(t *testing.T, cfgs ...rbconfig.Config) []rbtypes.Participant {
	t.Helper()
	participants := make([]rbtypes.Participant, 0, len(cfgs))
	for _, cfg := range cfgs {
		participants = append(participants, buildParticipant(t, cfg, rbtypes.ParticipantNode))
	}
	return participants
}

func buildParticipant(t *testing.T, cfg rbconfig.Config, participantType rbtypes.ParticipantType) rbtypes.Participant {
	t.Helper()
	store, err := rbstorage.NewLegacyIdentityStore(cfg.IdentityStorePath(), cfg.Storage.AgePassphrase)
	require.NoError(t, err)
	key, err := securecrypto.LoadOrCreateIdentity(store, cfg.IdentityRef(), rand.Reader)
	require.NoError(t, err)
	return rbtypes.Participant{
		ID:                   cfg.Runtime.ParticipantID,
		ParticipantType:      participantType,
		Moniker:              cfg.Runtime.ParticipantID,
		IdentityPublicKeyHex: strings.ToLower(hexString(key.PublicKey)),
	}
}

func waitForKeygenResult(t *testing.T, nc *nats.Conn, clientID, sessionID string, publish func()) rbtypes.KeygenResult {
	t.Helper()
	sub, err := nc.SubscribeSync(routing.KeygenResultSubject(clientID, sessionID))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	publish()
	msg, err := sub.NextMsg(20 * time.Second)
	require.NoError(t, err)
	var result rbtypes.KeygenResult
	require.NoError(t, json.Unmarshal(msg.Data, &result))
	return result
}

func waitForSignResult(t *testing.T, nc *nats.Conn, clientID, sessionID string, publish func()) rbtypes.SignResult {
	t.Helper()
	sub, err := nc.SubscribeSync(routing.SignResultSubject(clientID, sessionID))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	publish()
	msg, err := sub.NextMsg(20 * time.Second)
	require.NoError(t, err)
	var result rbtypes.SignResult
	require.NoError(t, json.Unmarshal(msg.Data, &result))
	return result
}

func publishForParticipants(
	t *testing.T,
	nc *nats.Conn,
	participants []rbtypes.Participant,
	walletID, sessionID string,
	operation rbtypes.Operation,
	value any,
	clientID string,
) {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	var protocol rbtypes.Protocol
	switch req := value.(type) {
	case rbtypes.KeygenRequest:
		protocol = req.Session.Protocol
	case rbtypes.SignRequest:
		protocol = req.Session.Protocol
	default:
		t.Fatalf("unsupported publish value type %T", value)
	}
	for _, participant := range participants {
		subject := routing.KeygenRequestSubject(participant.ID, walletID, protocol, sessionID)
		if operation == rbtypes.OperationSign {
			subject = routing.SignRequestSubject(participant.ID, walletID, protocol, sessionID)
		}
		require.NoError(t, nc.PublishMsg(&nats.Msg{
			Subject: subject,
			Data:    payload,
			Header:  nats.Header{event.ClientIDHeader: []string{clientID}},
		}))
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
	sub, err := nc.Subscribe("mpc.relay.to_cosigner.>", func(msg *nats.Msg) {
		subject := strings.Replace(msg.Subject, "mpc.relay.to_cosigner", "mpc.relay.from_cosigner", 1)
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

func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "e2e", "fixtures", name)
}

func hexString(blob []byte) string {
	const hextable = "0123456789abcdef"
	out := make([]byte, len(blob)*2)
	for i, b := range blob {
		out[i*2] = hextable[b>>4]
		out[i*2+1] = hextable[b&0x0f]
	}
	return string(out)
}
