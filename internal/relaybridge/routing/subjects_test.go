package routing

import (
	"testing"

	"github.com/fystack/mpcium/internal/relay/protocol"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResultSubscriptionSubjects(t *testing.T) {
	assert.Equal(t, "mpc.sdk.keygen.res.relaybridge-example.*", KeygenResultSubscriptionSubject("relaybridge-example"))
	assert.Equal(t, "mpc.sdk.sign.res.relaybridge-example.*", SignResultSubscriptionSubject("relaybridge-example"))
	assert.Equal(t, "mpc.sdk.*.res.relaybridge-example.*", ClientResultSubscriptionSubject("relaybridge-example"))
}

func TestDirectRequestSubjects(t *testing.T) {
	assert.Equal(t, "mpc.sdk.req.node0.wallet-1.ecdsa.keygen.session-1", KeygenRequestSubject("node0", "wallet-1", rbtypes.ProtocolECDSA, "session-1"))
	assert.Equal(t, "mpc.sdk.req.node0.wallet-1.eddsa.sign.session-2", SignRequestSubject("node0", "wallet-1", rbtypes.ProtocolEdDSA, "session-2"))
	assert.Equal(t, "mpc.sdk.req.node0.*.*.keygen.*", KeygenRequestFilterSubject("node0"))
	assert.Equal(t, "mpc.sdk.req.node0.*.*.sign.*", SignRequestFilterSubject("node0"))
}

func TestRelayRequestSubjects(t *testing.T) {
	assert.Equal(
		t,
		protocol.OutboundNATSSubject("node0", "wallet-1", "req", "ecdsa", "keygen", "session-1"),
		KeygenRelayRequestSubject("node0", "wallet-1", rbtypes.ProtocolECDSA, "session-1"),
	)
	assert.Equal(
		t,
		protocol.OutboundNATSSubject("node0", "wallet-1", "req", "eddsa", "sign", "session-2"),
		SignRelayRequestSubject("node0", "wallet-1", rbtypes.ProtocolEdDSA, "session-2"),
	)
}

func TestDirectSessionSubject(t *testing.T) {
	assert.Equal(
		t,
		"mpc.sdk.session.node0.wallet-1.ecdsa.sign.session-1.relaybridge",
		DirectSessionSubject("node0", "wallet-1", rbtypes.ProtocolECDSA, rbtypes.OperationSign, "session-1"),
	)
}

func TestParseDirectRequestSubject(t *testing.T) {
	target, err := ParseDirectRequestSubject("mpc.sdk.req.node0.wallet-1.eddsa.sign.session-1")
	require.NoError(t, err)
	assert.Equal(t, "node0", target.ParticipantID)
	assert.Equal(t, "wallet-1", target.WalletID)
	assert.Equal(t, rbtypes.ProtocolEdDSA, target.Protocol)
	assert.Equal(t, rbtypes.OperationSign, target.Operation)
	assert.Equal(t, "session-1", target.SessionID)
}

func TestParseRelayRequestSubject(t *testing.T) {
	target, err := ParseRelayRequestSubject(protocol.InboundNATSSubject("node0", "wallet-1", "req", "ecdsa", "sign", "session-1"))
	require.NoError(t, err)
	assert.Equal(t, "node0", target.ParticipantID)
	assert.Equal(t, "wallet-1", target.WalletID)
	assert.Equal(t, rbtypes.ProtocolECDSA, target.Protocol)
	assert.Equal(t, rbtypes.OperationSign, target.Operation)
	assert.Equal(t, "session-1", target.SessionID)
}
