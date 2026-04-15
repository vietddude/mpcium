package client

import (
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/fystack/mpcium/pkg/event"
	routing "github.com/fystack/mpcium/pkg/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKeygenPublishesRelayRequestForExternalParticipant(t *testing.T) {
	ns := startJetStreamTestServer(t)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	relaySub, err := nc.SubscribeSync(routing.KeygenRelayRequestSubject("cosigner-1", "wallet-1", rbtypes.ProtocolECDSA, "session-1"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = relaySub.Unsubscribe() })

	c := New(Options{
		NATSConn: nc,
		ClientID: "client-1",
	})
	t.Cleanup(c.Close)

	err = c.CreateKeygen(rbtypes.KeygenRequest{
		SessionID: "session-1",
		WalletID:  "wallet-1",
		Protocol:  rbtypes.ProtocolECDSA,
		Participants: []rbtypes.Participant{
			{ID: "node0", ParticipantType: rbtypes.ParticipantNode},
			{ID: "cosigner-1", ParticipantType: rbtypes.ParticipantServer},
		},
	})
	require.NoError(t, err)

	msg, err := relaySub.NextMsg(3 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "client-1", msg.Header.Get(event.ClientIDHeader))
}

func TestCreateKeygenWithoutProtocolPublishesECDSAAndEdDSA(t *testing.T) {
	ns := startJetStreamTestServer(t)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	ecdsaSub, err := nc.SubscribeSync(routing.KeygenRelayRequestSubject("cosigner-1", "wallet-1", rbtypes.ProtocolECDSA, "session-1-ecdsa"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ecdsaSub.Unsubscribe() })

	eddsaSub, err := nc.SubscribeSync(routing.KeygenRelayRequestSubject("cosigner-1", "wallet-1", rbtypes.ProtocolEdDSA, "session-1-eddsa"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = eddsaSub.Unsubscribe() })

	c := New(Options{
		NATSConn: nc,
		ClientID: "client-1",
	})
	t.Cleanup(c.Close)

	err = c.CreateKeygen(rbtypes.KeygenRequest{
		SessionID: "session-1",
		WalletID:  "wallet-1",
		Participants: []rbtypes.Participant{
			{ID: "node0", ParticipantType: rbtypes.ParticipantNode},
			{ID: "cosigner-1", ParticipantType: rbtypes.ParticipantServer},
		},
	})
	require.NoError(t, err)

	ecdsaMsg, err := ecdsaSub.NextMsg(3 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "client-1", ecdsaMsg.Header.Get(event.ClientIDHeader))
	assert.Equal(t, routing.KeygenRelayRequestSubject("cosigner-1", "wallet-1", rbtypes.ProtocolECDSA, "session-1-ecdsa"), ecdsaMsg.Subject)

	eddsaMsg, err := eddsaSub.NextMsg(3 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "client-1", eddsaMsg.Header.Get(event.ClientIDHeader))
	assert.Equal(t, routing.KeygenRelayRequestSubject("cosigner-1", "wallet-1", rbtypes.ProtocolEdDSA, "session-1-eddsa"), eddsaMsg.Subject)
}

func TestCreateKeygenPublishesSingleDirectRequest(t *testing.T) {
	ns := startJetStreamTestServer(t)

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	directSubject := routing.KeygenRequestSubject("wallet-1", rbtypes.ProtocolECDSA, "session-1")
	directSub, err := nc.SubscribeSync(directSubject)
	require.NoError(t, err)
	t.Cleanup(func() { _ = directSub.Unsubscribe() })

	c := New(Options{
		NATSConn: nc,
		ClientID: "client-1",
	})
	t.Cleanup(c.Close)

	err = c.CreateKeygen(rbtypes.KeygenRequest{
		SessionID: "session-1",
		WalletID:  "wallet-1",
		Protocol:  rbtypes.ProtocolECDSA,
		Participants: []rbtypes.Participant{
			{ID: "node0", ParticipantType: rbtypes.ParticipantNode},
			{ID: "node1", ParticipantType: rbtypes.ParticipantNode},
			{ID: "cosigner-1", ParticipantType: rbtypes.ParticipantServer},
		},
	})
	require.NoError(t, err)

	msg, err := directSub.NextMsg(3 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, directSubject, msg.Subject)
	assert.Equal(t, "client-1", msg.Header.Get(event.ClientIDHeader))

	_, err = directSub.NextMsg(200 * time.Millisecond)
	require.ErrorIs(t, err, nats.ErrTimeout)
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
