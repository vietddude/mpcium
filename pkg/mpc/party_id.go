package mpc

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/google/uuid"
)

// generatePartyIDs generates the party IDs for the given purpose and version
// It returns the self party ID and all party IDs
// It also sorts the party IDs in place
func (n *Node) generatePartyIDs(
	label string,
	readyPeerIDs []string,
	version int,
) (self *tss.PartyID, all []*tss.PartyID) {
	// Pre-allocate slice with exact size needed
	partyIDs := make([]*tss.PartyID, 0, len(readyPeerIDs))

	// Create all party IDs in one pass
	for _, peerID := range readyPeerIDs {
		partyID := createPartyID(peerID, label, version)
		if peerID == n.nodeID {
			self = partyID
		}
		partyIDs = append(partyIDs, partyID)
	}

	// Sort party IDs in place
	all = tss.SortPartyIDs(partyIDs, 0)
	return
}

// GeneratePartyIDsWithSelfLast behaves like GeneratePartyIDs but moves the
// node's own party ID to the end of the sorted slice. Keep persistence index for self mobile party.
func GeneratePartyIDsWithSelfLast(
	nodeID string,
	label string,
	readyPeerIDs []string,
	version int,
) (self *tss.PartyID, all []*tss.PartyID) {
	partyIDs := make([]*tss.PartyID, 0, len(readyPeerIDs))
	var selfParty *tss.PartyID

	// Create PartyID for all peers
	for _, peerID := range readyPeerIDs {
		partyID := createPartyID(peerID, label, version)
		if peerID == nodeID {
			selfParty = partyID
		} else {
			partyIDs = append(partyIDs, partyID)
		}
	}

	// Sort all PartyID except self
	partyIDs = tss.SortPartyIDs(partyIDs, 0)

	// Append self to the end of the slice
	if selfParty != nil {
		selfParty.Index = len(partyIDs)
		partyIDs = append(partyIDs, selfParty)
	}

	return selfParty, partyIDs
}

// / createPartyID creates a new party ID for the given node ID, label and version
// It returns the party ID: random string
// Moniker: for routing messages
// Key: for mpc internal use (need persistent storage)
func createPartyID(nodeID string, label string, version int) *tss.PartyID {
	partyID := uuid.NewString()
	var key *big.Int
	if version == BackwardCompatibleVersion {
		key = new(big.Int).SetBytes([]byte(nodeID))
	} else {
		keyBytes := fmt.Appendf(nil, "%s:%d", nodeID, version)
		key = new(big.Int).SetBytes(keyBytes)
	}
	return tss.NewPartyID(partyID, label, key)
}

func PartyIDToNodeID(partyID *tss.PartyID) string {
	if partyID == nil {
		return ""
	}
	nodeID, _, _ := strings.Cut(string(partyID.KeyInt().Bytes()), ":")
	return strings.TrimSpace(nodeID)
}

func PartyIDsToNodeIDs(pids []*tss.PartyID) []string {
	out := make([]string, 0, len(pids))
	for _, p := range pids {
		out = append(out, PartyIDToNodeID(p))
	}
	return out
}

func ComparePartyIDs(x, y *tss.PartyID) bool {
	return bytes.Equal(x.KeyInt().Bytes(), y.KeyInt().Bytes())
}
