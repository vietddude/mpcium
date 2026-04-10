package sdkflow

import (
	"testing"

	"github.com/fystack/mpcium/internal/relay"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClientID(t *testing.T) {
	assert.NoError(t, validateClientID(""))
	assert.NoError(t, validateClientID("svc-a"))
	assert.Error(t, validateClientID("svc a"))
	assert.Error(t, validateClientID("svc.a"))
}

func TestSelectedParticipants(t *testing.T) {
	participants := []Participant{
		{ID: "node0"},
		{ID: "node1"},
		{ID: "node2"},
	}

	selected, err := selectedParticipants(participants, []uint16{2, 0})
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "node2", selected[0].ID)
	assert.Equal(t, "node0", selected[1].ID)
}

func TestSelectedParticipantsOutOfRange(t *testing.T) {
	_, err := selectedParticipants([]Participant{{ID: "node0"}}, []uint16{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestValidateSignRequest(t *testing.T) {
	err := validateSignRequest(SignRequest{
		Session: SessionContext{
			SessionID:    "sign-1",
			WalletID:     "wallet-1",
			Protocol:     "ecdsa",
			Participants: []Participant{{ID: "node0"}},
		},
		SignerIndexes:    []uint16{0},
		MessageDigestHex: "aa",
	})
	require.NoError(t, err)
}

func TestResultSubscriptionSubjects(t *testing.T) {
	assert.Equal(t, "mpc.sdk.keygen.res.sdkflow-example.*", KeygenResultSubscriptionSubject("sdkflow-example"))
	assert.Equal(t, "mpc.sdk.sign.res.sdkflow-example.*", SignResultSubscriptionSubject("sdkflow-example"))
	assert.Equal(t, "mpc.sdk.*.res.sdkflow-example.*", ClientResultSubscriptionSubject("sdkflow-example"))
}

func TestDirectRequestSubjects(t *testing.T) {
	assert.Equal(
		t,
		"mpc.sdk.req.node0.wallet-1.keygen.session-1",
		KeygenRequestSubject("node0", "wallet-1", "session-1"),
	)
	assert.Equal(
		t,
		"mpc.sdk.req.node0.wallet-1.sign.session-2",
		SignRequestSubject("node0", "wallet-1", "session-2"),
	)
	assert.Equal(
		t,
		"mpc.sdk.req.node0.*.keygen.*",
		KeygenRequestFilterSubject("node0"),
	)
	assert.Equal(
		t,
		"mpc.sdk.req.node0.*.sign.*",
		SignRequestFilterSubject("node0"),
	)
}

func TestRelayRequestSubjects(t *testing.T) {
	assert.Equal(
		t,
		relay.OutboundNATSSubject("node0", "wallet-1", "req", "keygen", "session-1"),
		KeygenRelayRequestSubject("node0", "wallet-1", "session-1"),
	)
	assert.Equal(
		t,
		relay.OutboundNATSSubject("node0", "wallet-1", "req", "sign", "session-2"),
		SignRelayRequestSubject("node0", "wallet-1", "session-2"),
	)
}

func TestDirectSessionSubject(t *testing.T) {
	assert.Equal(
		t,
		"mpc.sdk.session.node0.wallet-1.sign.session-1.sdkflow",
		DirectSessionSubject("node0", "wallet-1", OperationSign, "session-1"),
	)
}

func TestParseDirectRequestSubject(t *testing.T) {
	target, err := ParseDirectRequestSubject("mpc.sdk.req.node0.wallet-1.sign.session-1")
	require.NoError(t, err)
	assert.Equal(t, "node0", target.ParticipantID)
	assert.Equal(t, "wallet-1", target.WalletID)
	assert.Equal(t, OperationSign, target.Operation)
	assert.Equal(t, "session-1", target.SessionID)
}

func TestParseRelayRequestSubject(t *testing.T) {
	target, err := ParseRelayRequestSubject(relay.InboundNATSSubject("node0", "wallet-1", "req", "sign", "session-1"))
	require.NoError(t, err)
	assert.Equal(t, "node0", target.ParticipantID)
	assert.Equal(t, "wallet-1", target.WalletID)
	assert.Equal(t, OperationSign, target.Operation)
	assert.Equal(t, "session-1", target.SessionID)
}
