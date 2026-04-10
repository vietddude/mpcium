package sdkflow

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
)

type Client interface {
	CreateKeygen(req KeygenRequest) error
	Sign(req SignRequest) error
	OnKeygenResult(callback func(result KeygenResult)) error
	OnSignResult(callback func(result SignResult)) error
	Close()
}

type ClientOptions struct {
	NatsConn *nats.Conn
	ClientID string
}

type client struct {
	keygenBroker      messaging.MessageBroker
	signBroker        messaging.MessageBroker
	keygenResultQueue messaging.MessageQueue
	signResultQueue   messaging.MessageQueue
	natsConn          *nats.Conn
	clientID          string
}

func NewClient(opts ClientOptions) Client {
	if opts.NatsConn == nil {
		logger.Fatal("NATS connection is required", nil)
	}
	if err := validateClientID(opts.ClientID); err != nil {
		logger.Fatal("Invalid client ID", err)
	}

	keygenBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NatsConn,
		KeygenRequestStream,
		[]string{KeygenRequestTopic()},
	)
	if err != nil {
		logger.Fatal("Failed to create sdkflow keygen broker", err)
	}
	signBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NatsConn,
		SignRequestStream,
		[]string{SignRequestTopic()},
	)
	if err != nil {
		logger.Fatal("Failed to create sdkflow sign broker", err)
	}

	mqManager := messaging.NewNATsMessageQueueManager(
		resultStreamName,
		ResultStreamSubjects(),
		opts.NatsConn,
	)
	keygenResultQueue := mqManager.NewMessageQueue(keygenResultConsumerName(opts.ClientID), KeygenResultSubscriptionSubject(opts.ClientID))
	signResultQueue := mqManager.NewMessageQueue(signResultConsumerName(opts.ClientID), SignResultSubscriptionSubject(opts.ClientID))

	return &client{
		keygenBroker:      keygenBroker,
		signBroker:        signBroker,
		keygenResultQueue: keygenResultQueue,
		signResultQueue:   signResultQueue,
		natsConn:          opts.NatsConn,
		clientID:          opts.ClientID,
	}
}

func (c *client) Close() {
	if c.keygenResultQueue != nil {
		c.keygenResultQueue.Close()
	}
	if c.signResultQueue != nil {
		c.signResultQueue.Close()
	}
	if c.keygenBroker != nil {
		_ = c.keygenBroker.Close()
	}
	if c.signBroker != nil {
		_ = c.signBroker.Close()
	}
}

func (c *client) CreateKeygen(req KeygenRequest) error {
	if err := validateKeygenRequest(req); err != nil {
		return err
	}
	logger.Info(
		"SDK flow client create keygen",
		"session_id", req.Session.SessionID,
		"wallet_id", req.Session.WalletID,
		"participants", len(req.Session.Participants),
	)

	for _, participant := range uniqueParticipants(req.Session.Participants) {
		localReq := req
		localReq.Session.LocalParticipantID = participant.ID
		if isExternalParticipant(participant) {
			if err := c.publishRelayRequest(participant.ID, req.Session.WalletID, OperationKeygen, req.Session.SessionID, localReq); err != nil {
				return fmt.Errorf("publish keygen request for %s via relay: %w", participant.ID, err)
			}
			logger.Info("SDK flow client published keygen request via relay", "participant_id", participant.ID, "session_id", req.Session.SessionID, "wallet_id", req.Session.WalletID)
			continue
		}
		if err := c.publishDirectRequest(participant.ID, req.Session.WalletID, OperationKeygen, req.Session.SessionID, localReq); err != nil {
			return fmt.Errorf("publish keygen request for %s via direct nats: %w", participant.ID, err)
		}
		logger.Info("SDK flow client published keygen request via direct nats", "participant_id", participant.ID, "session_id", req.Session.SessionID, "wallet_id", req.Session.WalletID)
	}
	return nil
}

func (c *client) Sign(req SignRequest) error {
	if err := validateSignRequest(req); err != nil {
		return err
	}
	recipients, err := selectedParticipants(req.Session.Participants, req.SignerIndexes)
	if err != nil {
		return err
	}
	logger.Info(
		"SDK flow client create sign",
		"session_id", req.Session.SessionID,
		"wallet_id", req.Session.WalletID,
		"participants", len(req.Session.Participants),
		"signers", req.SignerIndexes,
	)

	for _, participant := range uniqueParticipants(recipients) {
		localReq := req
		localReq.Session.LocalParticipantID = participant.ID
		if isExternalParticipant(participant) {
			if err := c.publishRelayRequest(participant.ID, req.Session.WalletID, OperationSign, req.Session.SessionID, localReq); err != nil {
				return fmt.Errorf("publish sign request for %s via relay: %w", participant.ID, err)
			}
			logger.Info("SDK flow client published sign request via relay", "participant_id", participant.ID, "session_id", req.Session.SessionID, "wallet_id", req.Session.WalletID)
			continue
		}
		if err := c.publishDirectRequest(participant.ID, req.Session.WalletID, OperationSign, req.Session.SessionID, localReq); err != nil {
			return fmt.Errorf("publish sign request for %s via direct nats: %w", participant.ID, err)
		}
		logger.Info("SDK flow client published sign request via direct nats", "participant_id", participant.ID, "session_id", req.Session.SessionID, "wallet_id", req.Session.WalletID)
	}
	return nil
}

func (c *client) OnKeygenResult(callback func(result KeygenResult)) error {
	return c.keygenResultQueue.Dequeue(
		KeygenResultSubscriptionSubject(c.clientID),
		func(message []byte) error {
			var result KeygenResult
			if err := json.Unmarshal(message, &result); err != nil {
				return err
			}
			callback(result)
			return nil
		},
	)
}

func (c *client) OnSignResult(callback func(result SignResult)) error {
	return c.signResultQueue.Dequeue(
		SignResultSubscriptionSubject(c.clientID),
		func(message []byte) error {
			var result SignResult
			if err := json.Unmarshal(message, &result); err != nil {
				return err
			}
			callback(result)
			return nil
		},
	)
}

func (c *client) requestHeaders() map[string]string {
	if c.clientID == "" {
		return nil
	}
	return map[string]string{
		event.ClientIDHeader: c.clientID,
	}
}

func resultConsumerName(clientID string) string {
	if clientID == "" {
		return resultStreamName
	}
	return resultStreamName + "." + clientID
}

func keygenResultConsumerName(clientID string) string {
	return resultConsumerName(clientID) + ".keygen"
}

func signResultConsumerName(clientID string) string {
	return resultConsumerName(clientID) + ".sign"
}

func (c *client) publishDirectRequest(
	participantID, walletID string,
	operation Operation,
	sessionID string,
	value any,
) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}

	var broker messaging.MessageBroker
	var subject string
	switch operation {
	case OperationKeygen:
		broker = c.keygenBroker
		subject = KeygenRequestSubject(participantID, walletID, sessionID)
	case OperationSign:
		broker = c.signBroker
		subject = SignRequestSubject(participantID, walletID, sessionID)
	default:
		return fmt.Errorf("unsupported request operation %q", operation)
	}
	return broker.PublishMessage(context.Background(), subject, payload, c.requestHeaders())
}

func (c *client) publishRelayRequest(
	participantID, walletID string,
	operation Operation,
	sessionID string,
	value any,
) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	msg := &nats.Msg{
		Subject: relayRequestSubject(participantID, walletID, operation, sessionID),
		Data:    payload,
	}
	if headers := c.requestHeaders(); len(headers) > 0 {
		msg.Header = nats.Header{}
		for key, value := range headers {
			msg.Header.Set(key, value)
		}
	}
	return c.natsConn.PublishMsg(msg)
}

func validateKeygenRequest(req KeygenRequest) error {
	if strings.TrimSpace(req.Session.SessionID) == "" {
		return fmt.Errorf("session.session_id is required")
	}
	if strings.TrimSpace(req.Session.WalletID) == "" {
		return fmt.Errorf("session.wallet_id is required")
	}
	if len(req.Session.Participants) == 0 {
		return fmt.Errorf("session.participants are required")
	}
	if strings.TrimSpace(string(req.Session.Protocol)) == "" {
		return fmt.Errorf("session.protocol is required")
	}
	return nil
}

func validateSignRequest(req SignRequest) error {
	if err := validateKeygenRequest(KeygenRequest{Session: req.Session}); err != nil {
		return err
	}
	if len(req.SignerIndexes) == 0 {
		return fmt.Errorf("signer_indexes are required")
	}
	if strings.TrimSpace(req.MessageDigestHex) == "" {
		return fmt.Errorf("message_digest_hex is required")
	}
	_, err := selectedParticipants(req.Session.Participants, req.SignerIndexes)
	return err
}

func selectedParticipants(
	participants []Participant,
	signerIndexes []uint16,
) ([]Participant, error) {
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

func validateClientID(clientID string) error {
	if clientID == "" {
		return nil
	}
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("client ID cannot be blank")
	}
	if strings.ContainsAny(clientID, " \t\r\n.*>") {
		return fmt.Errorf("client ID must be a single NATS subject token")
	}
	return nil
}

func uniqueParticipants(participants []Participant) []Participant {
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

func isExternalParticipant(participant Participant) bool {
	switch participant.ParticipantType {
	case ParticipantServer, ParticipantMobile:
		return true
	default:
		return false
	}
}

func isInternalNodeParticipant(participant Participant) bool {
	return !isExternalParticipant(participant)
}

func hasInternalNodeParticipants(participants []Participant) bool {
	return slices.ContainsFunc(participants, isInternalNodeParticipant)
}
