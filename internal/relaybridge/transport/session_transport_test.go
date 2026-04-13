package transport

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fystack/mpcium-sdk/mpcore"
	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/secure"
	"github.com/fystack/mpcium/internal/relay"
	routing "github.com/fystack/mpcium/internal/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNATSSessionEnvelopeTransportRoundTrip(t *testing.T) {
	ns := startJetStreamTestServer(t)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	transport := NewNATS(nc)
	subject := routing.DirectSessionSubject("alice", "wallet-1", rbtypes.ProtocolECDSA, rbtypes.OperationKeygen, "session-1")
	sub, err := transport.Subscribe([]string{subject})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Close() })

	envelope := protocol.Envelope{
		Version: protocol.EnvelopeVersion,
		Type:    protocol.EnvelopeTypeSession,
		Session: &protocol.SessionPayload{
			SessionID:    "session-1",
			WalletID:     "wallet-1",
			KeyType:      "ecdsa",
			Protocol:     "ecdsa",
			Operation:    "keygen",
			SenderID:     "bob",
			RecipientIDs: []string{"alice"},
			Message: secure.Message{
				Type: secure.MessageTypeSignedBroadcast,
				SignedBroadcast: &secure.SignedBroadcastMessage{
					Kind: secure.BroadcastKindKeyExchange,
					KeyExchange: &secure.KeyExchangeMessage{
						SessionID: "session-1",
						Protocol:  mpcore.ProtocolECDSA,
						Operation: mpcore.OperationKeygen,
						Round:     "key_exchange",
						FromIndex: 1,
						PublicKey: []byte{0x01, 0x02, 0x03},
					},
					Signature: []byte{0x09, 0x08, 0x07},
				},
			},
		},
	}

	require.NoError(t, transport.Publish(subject, envelope))

	select {
	case msg := <-sub.Messages():
		require.NoError(t, msg.Err)
		require.NotNil(t, msg.Envelope.Session)
		assert.Equal(t, envelope.Type, msg.Envelope.Type)
		assert.Equal(t, envelope.Session.SessionID, msg.Envelope.Session.SessionID)
		assert.Equal(t, envelope.Session.SenderID, msg.Envelope.Session.SenderID)
		assert.Equal(t, envelope.Session.RecipientIDs, msg.Envelope.Session.RecipientIDs)
		assert.Equal(t, envelope.Session.Message.Type, msg.Envelope.Session.Message.Type)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for session envelope")
	}
}

func TestNATSSessionEnvelopeTransportRelayCompatibility(t *testing.T) {
	ns := startJetStreamTestServer(t)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	transport := NewNATS(nc)
	outboundSubject := relay.OutboundNATSSubject("cosigner-1", "wallet-1", "ecdsa", "keygen", "session-1", "relaybridge")

	rawSub, err := nc.SubscribeSync(outboundSubject)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawSub.Unsubscribe() })

	envelope := protocol.Envelope{
		Version: protocol.EnvelopeVersion,
		Type:    protocol.EnvelopeTypeSession,
		Session: &protocol.SessionPayload{
			SessionID:    "session-1",
			WalletID:     "wallet-1",
			KeyType:      "ecdsa",
			Protocol:     "ecdsa",
			Operation:    "keygen",
			SenderID:     "alice",
			RecipientIDs: []string{"cosigner-1"},
			Message: secure.Message{
				Type: secure.MessageTypeSignedBroadcast,
				SignedBroadcast: &secure.SignedBroadcastMessage{
					Kind: secure.BroadcastKindKeyExchange,
					KeyExchange: &secure.KeyExchangeMessage{
						SessionID: "session-1",
						Protocol:  mpcore.ProtocolECDSA,
						Operation: mpcore.OperationKeygen,
						Round:     "key_exchange",
						FromIndex: 0,
						PublicKey: []byte{0x01, 0x02},
					},
					Signature: []byte{0x03},
				},
			},
		},
	}

	require.NoError(t, transport.Publish(outboundSubject, envelope))

	rawMsg, err := rawSub.NextMsg(3 * time.Second)
	require.NoError(t, err)

	var bridge relayBridgeEnvelope
	require.NoError(t, json.Unmarshal(rawMsg.Data, &bridge))
	assert.Equal(t, "secure", bridge.Kind)
	require.NotNil(t, bridge.Message)
	assert.Equal(t, envelope.Session.SenderID, bridge.SenderID)
	assert.Equal(t, envelope.Session.Message.Type, bridge.Message.Type)

	inboundSubject := relay.InboundNATSSubject("cosigner-1", "wallet-1", "ecdsa", "keygen", "session-2", "relaybridge")
	sub, err := transport.Subscribe([]string{inboundSubject})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Close() })

	require.NoError(t, nc.Publish(inboundSubject, mustJSON(t, relayBridgeEnvelope{
		SessionID: "session-2",
		WalletID:  "wallet-1",
		Protocol:  "ecdsa",
		Operation: "keygen",
		SenderID:  "cosigner-1",
		Kind:      "ready",
	})))

	select {
	case msg := <-sub.Messages():
		require.NoError(t, msg.Err)
		require.NotNil(t, msg.Envelope.Session)
		assert.True(t, IsReadyEnvelope(msg.Envelope))
		assert.Equal(t, "session-2", msg.Envelope.Session.SessionID)
		assert.Equal(t, "cosigner-1", msg.Envelope.Session.SenderID)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for relay bridge envelope")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	blob, err := json.Marshal(value)
	require.NoError(t, err)
	return blob
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
