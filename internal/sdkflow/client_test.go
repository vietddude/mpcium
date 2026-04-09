package sdkflow

import (
	"testing"

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
			Protocol:     "ecdsa",
			Participants: []Participant{{ID: "node0"}},
		},
		SignerIndexes:    []uint16{0},
		MessageDigestHex: "aa",
	})
	require.NoError(t, err)
}
