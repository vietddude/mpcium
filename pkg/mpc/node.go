package mpc

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

const (
	PurposeKeygen  string = "keygen"
	PurposeSign    string = "sign"
	PurposeReshare string = "reshare"

	BackwardCompatibleVersion int = 0
	DefaultVersion            int = 1
)

type ID string

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	ecdsaPreParams []*keygen.LocalPreParams
	identityStore  identity.Store
	peerRegistry   PeerRegistry
	ckd            *CKD
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
	ckd *CKD,
) *Node {
	start := time.Now()
	elapsed := time.Since(start)
	logger.Info("Starting new node, preparams is generated successfully!", "elapsed", elapsed.Milliseconds())

	node := &Node{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		direct:        direct,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		peerRegistry:  peerRegistry,
		identityStore: identityStore,
		ckd:           ckd,
	}
	node.ecdsaPreParams = node.generatePreParams()

	// Start watching peers - ECDH is now handled by the registry
	go peerRegistry.WatchPeersReady()
	return node
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) CreateKeyGenSession(
	sessionType SessionType,
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
	selectedNodeIDs []string,
) (KeyGenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, errors.New("All nodes are not ready!")
	}

	keyInfo, _ := p.getKeyInfo(sessionType, walletID)
	if keyInfo != nil {
		return nil, fmt.Errorf("Key already exists: %s", walletID)
	}

	var nodeIDs []string
	if len(selectedNodeIDs) > 0 {
		// Use selected node IDs, but filter to only include ready peers
		readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
		nodeIDs = p.filterReadyPeers(selectedNodeIDs, readyPeerIDs)
		
		// Validate that we have enough ready nodes
		if len(nodeIDs) < threshold+1 {
			return nil, fmt.Errorf("not enough ready nodes in selected list: expected at least %d, got %d", threshold+1, len(nodeIDs))
		}
		
		// Validate that self is in the selected list - return special error to skip, same as sign
		if !slices.Contains(nodeIDs, p.nodeID) {
			return nil, ErrNotInParticipantList
		}
	} else {
		// Use all ready peers if no selection provided
		nodeIDs = p.peerRegistry.GetReadyPeersIncludeSelf()
	}

	switch sessionType {
	case SessionTypeECDSA:
		return p.createECDSAKeyGenSession(walletID, threshold, DefaultVersion, resultQueue, nodeIDs)
	case SessionTypeEDDSA:
		return p.createEDDSAKeyGenSession(walletID, threshold, DefaultVersion, resultQueue, nodeIDs)
	default:
		return nil, fmt.Errorf("Unknown session type: %s", sessionType)
	}
}

func (p *Node) createECDSAKeyGenSession(walletID string, threshold int, version int, resultQueue messaging.MessageQueue, nodeIDs []string) (KeyGenSession, error) {
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, nodeIDs, version)
	session := newECDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		nodeIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams[0],
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) createEDDSAKeyGenSession(walletID string, threshold int, version int, resultQueue messaging.MessageQueue, nodeIDs []string) (KeyGenSession, error) {
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, nodeIDs, version)
	session := newEDDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		nodeIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateSigningSession(
	sessionType SessionType,
	walletID string,
	txID string,
	networkInternalCode string,
	resultQueue messaging.MessageQueue,
	derivationPath []uint32,
	idempotentKey string,
) (SigningSession, error) {
	version := p.getVersion(sessionType, walletID)
	keyInfo, err := p.getKeyInfo(sessionType, walletID)
	if err != nil {
		return nil, err
	}

	readyPeers := p.peerRegistry.GetReadyPeersIncludeSelf()
	readyParticipantIDs := p.getReadyPeersForSession(keyInfo, readyPeers)

	logger.Info("Creating signing session",
		"type", sessionType,
		"readyPeers", readyPeers,
		"participantPeerIDs", keyInfo.ParticipantPeerIDs,
		"ready count", len(readyParticipantIDs),
		"min ready", keyInfo.Threshold+1,
		"version", version,
	)

	if len(readyParticipantIDs) < keyInfo.Threshold+1 {
		return nil, fmt.Errorf("not enough peers to create signing session! expected %d, got %d", keyInfo.Threshold+1, len(readyParticipantIDs))
	}

	if err := p.ensureNodeIsParticipant(keyInfo); err != nil {
		return nil, err
	}

	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyParticipantIDs, version)

	switch sessionType {
	case SessionTypeECDSA:
		return newECDSASigningSession(
			walletID,
			txID,
			networkInternalCode,
			p.pubSub,
			p.direct,
			readyParticipantIDs,
			selfPartyID,
			allPartyIDs,
			keyInfo.Threshold,
			p.ecdsaPreParams[0],
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			derivationPath,
			idempotentKey,
			p.ckd,
		), nil

	case SessionTypeEDDSA:
		return newEDDSASigningSession(
			walletID,
			txID,
			networkInternalCode,
			p.pubSub,
			p.direct,
			readyParticipantIDs,
			selfPartyID,
			allPartyIDs,
			keyInfo.Threshold,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			derivationPath,
			idempotentKey,
			p.ckd,
		), nil
	}

	return nil, errors.New("unknown session type")
}

func (p *Node) getKeyInfo(sessionType SessionType, walletID string) (*keyinfo.KeyInfo, error) {
	var keyID string
	switch sessionType {
	case SessionTypeECDSA:
		keyID = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		keyID = fmt.Sprintf("eddsa:%s", walletID)
	default:
		return nil, errors.New("unsupported session type")
	}
	return p.keyinfoStore.Get(keyID)
}

func (p *Node) getReadyPeersForSession(keyInfo *keyinfo.KeyInfo, readyPeers []string) []string {
	// Ensure all participants are ready
	readyParticipantIDs := make([]string, 0, len(keyInfo.ParticipantPeerIDs))
	for _, peerID := range keyInfo.ParticipantPeerIDs {
		if slices.Contains(readyPeers, peerID) {
			readyParticipantIDs = append(readyParticipantIDs, peerID)
		}
	}

	return readyParticipantIDs
}

func (p *Node) filterReadyPeers(selectedNodeIDs []string, readyPeers []string) []string {
	// Filter selected node IDs to only include ready peers
	filtered := make([]string, 0, len(selectedNodeIDs))
	for _, nodeID := range selectedNodeIDs {
		if slices.Contains(readyPeers, nodeID) {
			filtered = append(filtered, nodeID)
		}
	}
	return filtered
}

func (p *Node) ensureNodeIsParticipant(keyInfo *keyinfo.KeyInfo) error {
	if !slices.Contains(keyInfo.ParticipantPeerIDs, p.nodeID) {
		return ErrNotInParticipantList
	}
	return nil
}

func (p *Node) CreateReshareSession(
	sessionType SessionType,
	walletID string,
	newThreshold int,
	newPeerIDs []string,
	isNewPeer bool,
	resultQueue messaging.MessageQueue,
) (ReshareSession, error) {
	// 1. Check peer readiness
	count := p.peerRegistry.GetReadyPeersCount()
	if count < int64(newThreshold)+1 {
		return nil, fmt.Errorf(
			"not enough peers to create reshare session! Expected at least %d, got %d",
			newThreshold+1,
			count,
		)
	}

	if len(newPeerIDs) < newThreshold+1 {
		return nil, fmt.Errorf("new peer list is smaller than required t+1")
	}

	// 2. Make sure all new peers are ready
	readyNewPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	for _, peerID := range newPeerIDs {
		if !slices.Contains(readyNewPeerIDs, peerID) {
			return nil, fmt.Errorf("new peer %s is not ready", peerID)
		}
	}

	// 3. Load old key info
	keyPrefix, err := sessionKeyPrefix(sessionType)
	if err != nil {
		return nil, fmt.Errorf("failed to get session key prefix: %w", err)
	}
	keyInfoKey := fmt.Sprintf("%s:%s", keyPrefix, walletID)
	oldKeyInfo, err := p.keyinfoStore.Get(keyInfoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get old key info: %w", err)
	}

	readyPeers := p.peerRegistry.GetReadyPeersIncludeSelf()
	readyOldParticipantIDs := p.getReadyPeersForSession(oldKeyInfo, readyPeers)

	isInOldCommittee := slices.Contains(oldKeyInfo.ParticipantPeerIDs, p.nodeID)
	isInNewCommittee := slices.Contains(newPeerIDs, p.nodeID)

	// 4. Skip if not relevant
	if isNewPeer && !isInNewCommittee {
		logger.Info("Skipping new session: node is not in new committee", "walletID", walletID, "nodeID", p.nodeID)
		return nil, nil
	}
	if !isNewPeer && !isInOldCommittee {
		logger.Info("Skipping old session: node is not in old committee", "walletID", walletID, "nodeID", p.nodeID)
		return nil, nil
	}

	logger.Info("Creating resharing session",
		"type", sessionType,
		"readyPeers", readyPeers,
		"participantPeerIDs", oldKeyInfo.ParticipantPeerIDs,
		"ready count", len(readyOldParticipantIDs),
		"min ready", oldKeyInfo.Threshold+1,
		"version", oldKeyInfo.Version,
		"isNewPeer", isNewPeer,
	)

	if len(readyOldParticipantIDs) < oldKeyInfo.Threshold+1 {
		return nil, fmt.Errorf("not enough peers to create resharing session! expected %d, got %d", oldKeyInfo.Threshold+1, len(readyOldParticipantIDs))
	}

	if !isNewPeer {
		if err := p.ensureNodeIsParticipant(oldKeyInfo); err != nil {
			return nil, err
		}
	}

	// 5. Generate party IDs
	version := p.getVersion(sessionType, walletID)
	oldSelf, oldAllPartyIDs := p.generatePartyIDs(PurposeKeygen, readyOldParticipantIDs, version)
	newSelf, newAllPartyIDs := p.generatePartyIDs(PurposeReshare, newPeerIDs, version+1)

	// 6. Pick identity and call session constructor
	var selfPartyID *tss.PartyID
	var participantPeerIDs []string
	if isNewPeer {
		selfPartyID = newSelf
		participantPeerIDs = newPeerIDs
	} else {
		selfPartyID = oldSelf
		participantPeerIDs = readyOldParticipantIDs
	}

	switch sessionType {
	case SessionTypeECDSA:
		preParams := p.ecdsaPreParams[0]
		if isNewPeer {
			preParams = p.ecdsaPreParams[1]
			participantPeerIDs = newPeerIDs
		} else {
			participantPeerIDs = oldKeyInfo.ParticipantPeerIDs
		}

		return NewECDSAReshareSession(
			walletID,
			p.pubSub,
			p.direct,
			participantPeerIDs,
			selfPartyID,
			oldAllPartyIDs,
			newAllPartyIDs,
			oldKeyInfo.Threshold,
			newThreshold,
			preParams,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			newPeerIDs,
			isNewPeer,
			oldKeyInfo.Version,
		), nil

	case SessionTypeEDDSA:
		return NewEDDSAReshareSession(
			walletID,
			p.pubSub,
			p.direct,
			participantPeerIDs,
			selfPartyID,
			oldAllPartyIDs,
			newAllPartyIDs,
			oldKeyInfo.Threshold,
			newThreshold,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			newPeerIDs,
			isNewPeer,
			oldKeyInfo.Version,
		), nil

	default:
		return nil, fmt.Errorf("unsupported session type: %v", sessionType)
	}
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func (p *Node) Close() {
	err := p.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}

func (p *Node) generatePreParams() []*keygen.LocalPreParams {
	start := time.Now()
	// Try to load from kvstore
	preParams := make([]*keygen.LocalPreParams, 2)
	for i := 0; i < 2; i++ {
		key := fmt.Sprintf("pre_params_%d", i)
		val, err := p.kvstore.Get(key)
		if err == nil && val != nil {
			preParams[i] = &keygen.LocalPreParams{}
			err = json.Unmarshal(val, preParams[i])
			if err != nil {
				logger.Fatal("Unmarshal pre params failed", err)
			}
			continue
		}
		// Not found, generate and save
		params, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			logger.Fatal("Generate pre params failed", err)
		}
		bytes, err := json.Marshal(params)
		if err != nil {
			logger.Fatal("Marshal pre params failed", err)
		}
		err = p.kvstore.Put(key, bytes)
		if err != nil {
			logger.Fatal("Save pre params failed", err)
		}
		preParams[i] = params
	}
	logger.Info("Generate pre params successfully!", "elapsed", time.Since(start).Milliseconds())
	return preParams
}

func (p *Node) getVersion(sessionType SessionType, walletID string) int {
	var composeKey string
	switch sessionType {
	case SessionTypeECDSA:
		composeKey = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		composeKey = fmt.Sprintf("eddsa:%s", walletID)
	default:
		logger.Fatal("Unknown session type", errors.New("Unknown session type"))
	}
	keyinfo, err := p.keyinfoStore.Get(composeKey)
	if err != nil {
		logger.Error("Get keyinfo failed", err, "walletID", walletID)
		return DefaultVersion
	}
	return keyinfo.Version
}

func sessionKeyPrefix(sessionType SessionType) (string, error) {
	switch sessionType {
	case SessionTypeECDSA:
		return "ecdsa", nil
	case SessionTypeEDDSA:
		return "eddsa", nil
	default:
		return "", fmt.Errorf("unsupported session type: %v", sessionType)
	}
}
