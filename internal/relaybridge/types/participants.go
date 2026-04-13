package types

import (
	"fmt"
	"slices"
	"strings"
)

func ContainsParticipantID(participants []Participant, participantID string) bool {
	participantID = strings.TrimSpace(participantID)
	for _, participant := range participants {
		if strings.TrimSpace(participant.ID) == participantID {
			return true
		}
	}
	return false
}

func UniqueParticipants(participants []Participant) []Participant {
	unique := make([]Participant, 0, len(participants))
	seen := make(map[string]struct{}, len(participants))
	for _, participant := range participants {
		id := strings.TrimSpace(participant.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, participant)
	}
	return unique
}

func SelectedParticipants(participants []Participant, signerIndexes []uint16) ([]Participant, error) {
	selected := make([]Participant, 0, len(signerIndexes))
	seen := make(map[uint16]struct{}, len(signerIndexes))
	for _, idx := range signerIndexes {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		if int(idx) >= len(participants) {
			return nil, fmt.Errorf("signer index %d out of range", idx)
		}
		selected = append(selected, participants[idx])
	}
	return selected, nil
}

func PreferredReporter(participants []Participant) string {
	if len(participants) == 0 {
		return ""
	}

	candidates := make([]Participant, 0, len(participants))
	for _, participant := range participants {
		if participant.ParticipantType == ParticipantNode || participant.ParticipantType == "" {
			candidates = append(candidates, participant)
		}
	}
	if len(candidates) == 0 {
		candidates = append(candidates, participants...)
	}

	slices.SortFunc(candidates, func(a, b Participant) int {
		return strings.Compare(strings.TrimSpace(a.ID), strings.TrimSpace(b.ID))
	})
	return strings.TrimSpace(candidates[0].ID)
}
