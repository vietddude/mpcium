package client

import (
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	routing "github.com/fystack/mpcium/internal/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/fystack/mpcium/pkg/event"
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
		Session: rbtypes.SessionContext{
			SessionID: "session-1",
			WalletID:  "wallet-1",
			Protocol:  rbtypes.ProtocolECDSA,
			Participants: []rbtypes.Participant{
				{ID: "node0", ParticipantType: rbtypes.ParticipantNode},
				{ID: "cosigner-1", ParticipantType: rbtypes.ParticipantServer},
			},
		},
	})
	require.NoError(t, err)

	msg, err := relaySub.NextMsg(3 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "client-1", msg.Header.Get(event.ClientIDHeader))
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
