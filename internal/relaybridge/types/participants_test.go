package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectedParticipants(t *testing.T) {
	participants := []Participant{
		{ID: "node1"},
		{ID: "node0"},
		{ID: "cosigner-1"},
	}

	selected, err := SelectedParticipants(participants, []uint16{1, 2, 1})
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "node0", selected[0].ID)
	assert.Equal(t, "cosigner-1", selected[1].ID)
}

func TestPreferredReporterPrefersInternalNodeByID(t *testing.T) {
	participants := []Participant{
		{ID: "node2", ParticipantType: ParticipantNode},
		{ID: "cosigner-1", ParticipantType: ParticipantServer},
		{ID: "node0", ParticipantType: ParticipantNode},
	}

	assert.Equal(t, "node0", PreferredReporter(participants))
}

func TestUniqueParticipants(t *testing.T) {
	participants := []Participant{
		{ID: "node0"},
		{ID: "node0"},
		{ID: ""},
		{ID: "node1"},
	}

	unique := UniqueParticipants(participants)
	require.Len(t, unique, 2)
	assert.Equal(t, "node0", unique[0].ID)
	assert.Equal(t, "node1", unique[1].ID)
}
