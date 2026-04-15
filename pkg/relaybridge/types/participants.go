package types

import (
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

func ParticipantByID(participants []Participant, participantID string) (Participant, bool) {
	participantID = strings.TrimSpace(participantID)
	for _, participant := range participants {
		if strings.TrimSpace(participant.ID) == participantID {
			return participant, true
		}
	}
	return Participant{}, false
}

func IsExternalParticipant(participant Participant) bool {
	return participant.ParticipantType == ParticipantServer ||
		participant.ParticipantType == ParticipantMobile
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
