package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	routing "github.com/fystack/mpcium/pkg/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
	"github.com/nats-io/nats.go"
)

type Client interface {
	CreateKeygen(req rbtypes.KeygenRequest) error
	Sign(req rbtypes.SignRequest) error
	OnKeygenResult(callback func(result rbtypes.KeygenResult)) error
	OnSignResult(callback func(result rbtypes.SignResult)) error
	Close()
}

type Options struct {
	NATSConn *nats.Conn
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

func New(opts Options) Client {
	if opts.NATSConn == nil {
		logger.Fatal("NATS connection is required", nil)
	}
	if err := validateClientID(opts.ClientID); err != nil {
		logger.Fatal("Invalid client ID", err)
	}

	keygenBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NATSConn,
		routing.KeygenRequestStream,
		[]string{routing.KeygenRequestTopic()},
	)
	if err != nil {
		logger.Fatal("Failed to create relaybridge keygen broker", err)
	}

	signBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NATSConn,
		routing.SignRequestStream,
		[]string{routing.SignRequestTopic()},
	)
	if err != nil {
		logger.Fatal("Failed to create relaybridge sign broker", err)
	}

	mqManager := messaging.NewNATsMessageQueueManager(
		routing.ResultStreamName,
		routing.ResultStreamSubjects(),
		opts.NATSConn,
	)

	return &client{
		keygenBroker:      keygenBroker,
		signBroker:        signBroker,
		keygenResultQueue: mqManager.NewMessageQueue(keygenResultConsumerName(opts.ClientID), routing.KeygenResultSubscriptionSubject(opts.ClientID)),
		signResultQueue:   mqManager.NewMessageQueue(signResultConsumerName(opts.ClientID), routing.SignResultSubscriptionSubject(opts.ClientID)),
		natsConn:          opts.NATSConn,
		clientID:          opts.ClientID,
	}
}

func (c *client) Close() {
	c.keygenResultQueue.Close()
	c.signResultQueue.Close()
	_ = c.keygenBroker.Close()
	_ = c.signBroker.Close()
}

func (c *client) CreateKeygen(req rbtypes.KeygenRequest) error {
	if err := validateKeygenRequest(req); err != nil {
		return err
	}
	for _, protocol := range requestedKeygenProtocols(req.Protocol) {
		protocolReq := keygenRequestForProtocol(req, protocol)
		sessionID := protocolReq.SessionID
		directParticipants, relayParticipants := splitParticipants(req.Participants)
		logger.Info("relaybridge client create keygen",
			"session_id", sessionID,
			"wallet_id", req.WalletID,
			"participants", len(req.Participants),
			"protocol", protocol,
		)
		if len(directParticipants) > 0 {
			if err := c.publishDirectRequest(protocolReq); err != nil {
				return err
			}
			logger.Info(
				"relaybridge client published keygen direct request",
				"session_id", sessionID,
				"wallet_id", req.WalletID,
			)
		}
		if err := c.publishRelayRequests(
			relayParticipants,
			req.WalletID,
			protocol,
			rbtypes.OperationKeygen,
			sessionID,
			protocolReq,
		); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) Sign(req rbtypes.SignRequest) error {
	if err := validateSignRequest(req); err != nil {
		return err
	}
	directParticipants, relayParticipants := splitParticipants(req.Participants)
	logger.Info("relaybridge client create sign",
		"session_id", req.SessionID,
		"wallet_id", req.WalletID,
		"participants", len(req.Participants),
	)
	if len(directParticipants) > 0 {
		if err := c.publishDirectRequest(req); err != nil {
			return err
		}
		logger.Info(
			"relaybridge client published sign direct request",
			"session_id", req.SessionID,
			"wallet_id", req.WalletID,
		)
	}
	return c.publishRelayRequests(
		relayParticipants,
		req.WalletID,
		req.Protocol,
		rbtypes.OperationSign,
		req.SessionID,
		req,
	)
}

func (c *client) OnKeygenResult(callback func(result rbtypes.KeygenResult)) error {
	return c.keygenResultQueue.Dequeue(
		routing.KeygenResultSubscriptionSubject(c.clientID),
		func(message []byte) error {
			var result rbtypes.KeygenResult
			if err := json.Unmarshal(message, &result); err != nil {
				return err
			}
			callback(result)
			return nil
		},
	)
}

func (c *client) OnSignResult(callback func(result rbtypes.SignResult)) error {
	return c.signResultQueue.Dequeue(
		routing.SignResultSubscriptionSubject(c.clientID),
		func(message []byte) error {
			var result rbtypes.SignResult
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
	return map[string]string{event.ClientIDHeader: c.clientID}
}

func (c *client) publishRelayRequests(
	participants []rbtypes.Participant,
	walletID string,
	protocol rbtypes.Protocol,
	operation rbtypes.Operation,
	sessionID string,
	value any,
) error {
	if len(participants) == 0 {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	for _, participant := range participants {
		if err := c.publishRelayPayload(participant.ID, walletID, protocol, operation, sessionID, payload); err != nil {
			return fmt.Errorf("publish %s request for %s via relay: %w", operation, participant.ID, err)
		}
		logger.Info(
			fmt.Sprintf("relaybridge client published %s request via relay", operation),
			"participant_id", participant.ID,
			"session_id", sessionID,
			"wallet_id", walletID,
		)
	}
	return nil
}

func (c *client) publishDirectRequest(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var broker messaging.MessageBroker
	var subject string
	switch req := value.(type) {
	case rbtypes.KeygenRequest:
		broker = c.keygenBroker
		subject = routing.KeygenRequestSubject(req.WalletID, req.Protocol, req.SessionID)
	case rbtypes.SignRequest:
		broker = c.signBroker
		subject = routing.SignRequestSubject(req.WalletID, req.Protocol, req.SessionID)
	default:
		return fmt.Errorf("unsupported direct request type %T", value)
	}
	return broker.PublishMessage(context.Background(), subject, payload, c.requestHeaders())
}

func (c *client) publishRelayPayload(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string, payload []byte) error {
	var subject string
	switch operation {
	case rbtypes.OperationKeygen:
		subject = routing.KeygenRelayRequestSubject(participantID, walletID, protocol, sessionID)
	case rbtypes.OperationSign:
		subject = routing.SignRelayRequestSubject(participantID, walletID, protocol, sessionID)
	default:
		return fmt.Errorf("unsupported operation %q", operation)
	}
	msg := &nats.Msg{Subject: subject, Data: payload}
	if headers := c.requestHeaders(); len(headers) > 0 {
		msg.Header = nats.Header{}
		for key, value := range headers {
			msg.Header.Set(key, value)
		}
	}
	return c.natsConn.PublishMsg(msg)
}

func keygenResultConsumerName(clientID string) string {
	base := routing.ResultStreamName
	if clientID != "" {
		base += "." + clientID
	}
	return base + ".keygen"
}

func signResultConsumerName(clientID string) string {
	base := routing.ResultStreamName
	if clientID != "" {
		base += "." + clientID
	}
	return base + ".sign"
}

func validateKeygenRequest(req rbtypes.KeygenRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(req.WalletID) == "" {
		return fmt.Errorf("wallet_id is required")
	}
	if len(req.Participants) == 0 {
		return fmt.Errorf("participants are required")
	}
	return validateOptionalKeygenProtocol(req.Protocol)
}

func validateSignRequest(req rbtypes.SignRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(req.WalletID) == "" {
		return fmt.Errorf("wallet_id is required")
	}
	if len(req.Participants) == 0 {
		return fmt.Errorf("participants are required")
	}
	switch rbtypes.Protocol(strings.ToLower(strings.TrimSpace(string(req.Protocol)))) {
	case rbtypes.ProtocolECDSA, rbtypes.ProtocolEdDSA:
	default:
		return fmt.Errorf("protocol must be ecdsa or eddsa")
	}
	if len(req.MessageDigest) == 0 {
		return fmt.Errorf("message_digest is required")
	}
	return nil
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

func splitParticipants(participants []rbtypes.Participant) ([]rbtypes.Participant, []rbtypes.Participant) {
	unique := rbtypes.UniqueParticipants(participants)
	direct := make([]rbtypes.Participant, 0, len(unique))
	relay := make([]rbtypes.Participant, 0, len(unique))
	for _, participant := range unique {
		if rbtypes.IsExternalParticipant(participant) {
			relay = append(relay, participant)
			continue
		}
		direct = append(direct, participant)
	}
	return direct, relay
}

func requestedKeygenProtocols(protocol rbtypes.Protocol) []rbtypes.Protocol {
	normalized := rbtypes.Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))
	if normalized == "" {
		return []rbtypes.Protocol{rbtypes.ProtocolECDSA, rbtypes.ProtocolEdDSA}
	}
	return []rbtypes.Protocol{normalized}
}

func validateOptionalKeygenProtocol(protocol rbtypes.Protocol) error {
	switch rbtypes.Protocol(strings.ToLower(strings.TrimSpace(string(protocol)))) {
	case "", rbtypes.ProtocolECDSA, rbtypes.ProtocolEdDSA:
		return nil
	default:
		return fmt.Errorf("session.protocol must be ecdsa or eddsa")
	}
}

func keygenSessionID(base string, requested rbtypes.Protocol, actual rbtypes.Protocol) string {
	if strings.TrimSpace(base) == "" || strings.TrimSpace(string(requested)) != "" {
		return base
	}
	return base + "-" + string(actual)
}

func keygenRequestForProtocol(req rbtypes.KeygenRequest, protocol rbtypes.Protocol) rbtypes.KeygenRequest {
	protocolReq := req
	protocolReq.Protocol = protocol
	protocolReq.SessionID = keygenSessionID(req.SessionID, req.Protocol, protocol)
	return protocolReq
}
