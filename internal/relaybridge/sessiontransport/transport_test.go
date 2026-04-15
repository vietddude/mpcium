package sessiontransport

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fystack/mpcium-sdk/mpcore"
	"github.com/fystack/mpcium-sdk/secure"
	relayprotocol "github.com/fystack/mpcium/internal/relay/protocol"
	routing "github.com/fystack/mpcium/pkg/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
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

	envelope := Payload{
		SessionID:    "session-1",
		WalletID:     "wallet-1",
		Protocol:     "ecdsa",
		Operation:    "keygen",
		SenderID:     "bob",
		RecipientIDs: []string{"alice"},
		Message: secure.Message{
			Type: secure.MessageTypeSignedBroadcast,
			SignedBroadcast: &secure.SignedBroadcastMessage{
				Kind: secure.BroadcastKindKeyExchange,
				KeyExchange: &secure.KeyExchangeMessage{
					SessionID:         "session-1",
					Protocol:          mpcore.ProtocolECDSA,
					Operation:         mpcore.OperationKeygen,
					Round:             "key_exchange",
					FromParticipantID: "bob",
					PublicKey:         []byte{0x01, 0x02, 0x03},
				},
				Signature: []byte{0x09, 0x08, 0x07},
			},
		},
	}

	require.NoError(t, transport.Publish(subject, envelope))

	select {
	case msg := <-sub.Messages():
		require.NoError(t, msg.Err)
		assert.Equal(t, envelope.SessionID, msg.Payload.SessionID)
		assert.Equal(t, envelope.SenderID, msg.Payload.SenderID)
		assert.Equal(t, envelope.RecipientIDs, msg.Payload.RecipientIDs)
		assert.Equal(t, envelope.Message.Type, msg.Payload.Message.Type)
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
	outboundSubject := relayprotocol.OutboundNATSSubject("cosigner-1", "wallet-1", "ecdsa", "keygen", "session-1", "relaybridge")

	rawSub, err := nc.SubscribeSync(outboundSubject)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawSub.Unsubscribe() })

	envelope := Payload{
		SessionID:    "session-1",
		WalletID:     "wallet-1",
		Protocol:     "ecdsa",
		Operation:    "keygen",
		SenderID:     "alice",
		RecipientIDs: []string{"cosigner-1"},
		Message: secure.Message{
			Type: secure.MessageTypeSignedBroadcast,
			SignedBroadcast: &secure.SignedBroadcastMessage{
				Kind: secure.BroadcastKindKeyExchange,
				KeyExchange: &secure.KeyExchangeMessage{
					SessionID:         "session-1",
					Protocol:          mpcore.ProtocolECDSA,
					Operation:         mpcore.OperationKeygen,
					Round:             "key_exchange",
					FromParticipantID: "alice",
					PublicKey:         []byte{0x01, 0x02},
				},
				Signature: []byte{0x03},
			},
		},
	}

	require.NoError(t, transport.Publish(outboundSubject, envelope))

	rawMsg, err := rawSub.NextMsg(3 * time.Second)
	require.NoError(t, err)

	var forwarded Payload
	require.NoError(t, json.Unmarshal(rawMsg.Data, &forwarded))
	assert.Equal(t, envelope.SenderID, forwarded.SenderID)
	assert.Equal(t, envelope.RecipientIDs, forwarded.RecipientIDs)
	assert.Equal(t, envelope.Message.Type, forwarded.Message.Type)

	inboundSubject := relayprotocol.InboundNATSSubject("cosigner-1", "wallet-1", "ecdsa", "keygen", "session-2", "relaybridge")
	sub, err := transport.Subscribe([]string{inboundSubject})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Close() })

	require.NoError(t, nc.Publish(inboundSubject, mustJSON(t, Payload{
		SessionID:    "session-2",
		WalletID:     "wallet-1",
		Protocol:     "ecdsa",
		Operation:    "keygen",
		SenderID:     "cosigner-1",
		RecipientIDs: []string{"alice"},
		Message: secure.Message{
			Type: secure.MessageTypeSignedBroadcast,
			SignedBroadcast: &secure.SignedBroadcastMessage{
				Kind: secure.BroadcastKindKeyExchange,
				KeyExchange: &secure.KeyExchangeMessage{
					SessionID:         "session-2",
					Protocol:          mpcore.ProtocolECDSA,
					Operation:         mpcore.OperationKeygen,
					Round:             "key_exchange",
					FromParticipantID: "cosigner-1",
					PublicKey:         []byte{0x09, 0x08},
				},
				Signature: []byte{0x07},
			},
		},
	})))

	select {
	case msg := <-sub.Messages():
		require.NoError(t, msg.Err)
		assert.Equal(t, "session-2", msg.Payload.SessionID)
		assert.Equal(t, "cosigner-1", msg.Payload.SenderID)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for relay bridge envelope")
	}
}

func TestNATSSessionEnvelopeTransportRejectsEmptyMessageType(t *testing.T) {
	ns := startJetStreamTestServer(t)
	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	transport := NewNATS(nc)
	subject := routing.DirectSessionSubject("alice", "wallet-1", rbtypes.ProtocolECDSA, rbtypes.OperationKeygen, "session-1")
	err = transport.Publish(subject, Payload{
		SessionID:    "session-1",
		WalletID:     "wallet-1",
		Protocol:     "ecdsa",
		Operation:    "keygen",
		SenderID:     "bob",
		RecipientIDs: []string{"alice"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message.type is required")
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
