package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	routing "github.com/fystack/mpcium/internal/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
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
	keygenResultQueue := mqManager.NewMessageQueue(keygenResultConsumerName(opts.ClientID), routing.KeygenResultSubscriptionSubject(opts.ClientID))
	signResultQueue := mqManager.NewMessageQueue(signResultConsumerName(opts.ClientID), routing.SignResultSubscriptionSubject(opts.ClientID))

	return &client{
		keygenBroker:      keygenBroker,
		signBroker:        signBroker,
		keygenResultQueue: keygenResultQueue,
		signResultQueue:   signResultQueue,
		natsConn:          opts.NATSConn,
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

func (c *client) CreateKeygen(req rbtypes.KeygenRequest) error {
	if err := validateKeygenRequest(req); err != nil {
		return err
	}
	logger.Info(
		"mpcium-relaybridge client create keygen",
		"session_id", req.Session.SessionID,
		"wallet_id", req.Session.WalletID,
		"participants", len(req.Session.Participants),
	)
	return c.publishRequests(
		rbtypes.UniqueParticipants(req.Session.Participants),
		req.Session.WalletID,
		req.Session.Protocol,
		rbtypes.OperationKeygen,
		req.Session.SessionID,
		func(participantID string) any {
			localReq := req
			localReq.Session.LocalParticipantID = participantID
			return localReq
		},
	)
}

func (c *client) Sign(req rbtypes.SignRequest) error {
	if err := validateSignRequest(req); err != nil {
		return err
	}
	recipients, err := rbtypes.SelectedParticipants(req.Session.Participants, req.SignerIndexes)
	if err != nil {
		return err
	}
	logger.Info(
		"mpcium-relaybridge client create sign",
		"session_id", req.Session.SessionID,
		"wallet_id", req.Session.WalletID,
		"participants", len(req.Session.Participants),
		"signers", req.SignerIndexes,
	)
	return c.publishRequests(
		rbtypes.UniqueParticipants(recipients),
		req.Session.WalletID,
		req.Session.Protocol,
		rbtypes.OperationSign,
		req.Session.SessionID,
		func(participantID string) any {
			localReq := req
			localReq.Session.LocalParticipantID = participantID
			return localReq
		},
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
	return map[string]string{
		event.ClientIDHeader: c.clientID,
	}
}

func resultConsumerName(clientID string) string {
	if clientID == "" {
		return routing.ResultStreamName
	}
	return routing.ResultStreamName + "." + clientID
}

func keygenResultConsumerName(clientID string) string {
	return resultConsumerName(clientID) + ".keygen"
}

func signResultConsumerName(clientID string) string {
	return resultConsumerName(clientID) + ".sign"
}

func (c *client) publishRequests(
	participants []rbtypes.Participant,
	walletID string,
	protocol rbtypes.Protocol,
	operation rbtypes.Operation,
	sessionID string,
	build func(participantID string) any,
) error {
	for _, participant := range participants {
		if err := c.publishRequest(participant, walletID, protocol, operation, sessionID, build(participant.ID)); err != nil {
			route := "direct nats"
			if isExternalParticipant(participant) {
				route = "relay"
			}
			return fmt.Errorf("publish %s request for %s via %s: %w", operation, participant.ID, route, err)
		}
		logRequestPublish(operation, participant.ID, sessionID, walletID, isExternalParticipant(participant))
	}
	return nil
}

func (c *client) publishRequest(
	participant rbtypes.Participant,
	walletID string,
	protocol rbtypes.Protocol,
	operation rbtypes.Operation,
	sessionID string,
	value any,
) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if isExternalParticipant(participant) {
		return c.publishRelayPayload(participant.ID, walletID, protocol, operation, sessionID, payload)
	}
	return c.publishDirectPayload(participant.ID, walletID, protocol, operation, sessionID, payload)
}

func (c *client) publishDirectPayload(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string, payload []byte) error {
	var broker messaging.MessageBroker
	var subject string
	switch operation {
	case rbtypes.OperationKeygen:
		broker = c.keygenBroker
		subject = routing.KeygenRequestSubject(participantID, walletID, protocol, sessionID)
	case rbtypes.OperationSign:
		broker = c.signBroker
		subject = routing.SignRequestSubject(participantID, walletID, protocol, sessionID)
	default:
		return fmt.Errorf("unsupported request operation %q", operation)
	}
	return broker.PublishMessage(context.Background(), subject, payload, c.requestHeaders())
}

func (c *client) publishRelayPayload(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string, payload []byte) error {
	msg := &nats.Msg{
		Subject: relayRequestSubject(participantID, walletID, protocol, operation, sessionID),
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

func relayRequestSubject(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string) string {
	switch operation {
	case rbtypes.OperationKeygen:
		return routing.KeygenRelayRequestSubject(participantID, walletID, protocol, sessionID)
	case rbtypes.OperationSign:
		return routing.SignRelayRequestSubject(participantID, walletID, protocol, sessionID)
	default:
		return ""
	}
}

func logRequestPublish(operation rbtypes.Operation, participantID, sessionID, walletID string, viaRelay bool) {
	route := "direct nats"
	if viaRelay {
		route = "relay"
	}
	logger.Info(
		fmt.Sprintf("mpcium-relaybridge client published %s request via %s", operation, route),
		"participant_id", participantID,
		"session_id", sessionID,
		"wallet_id", walletID,
	)
}

func validateKeygenRequest(req rbtypes.KeygenRequest) error {
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

func validateSignRequest(req rbtypes.SignRequest) error {
	if err := validateKeygenRequest(rbtypes.KeygenRequest{Session: req.Session}); err != nil {
		return err
	}
	if len(req.SignerIndexes) == 0 {
		return fmt.Errorf("signer_indexes are required")
	}
	if strings.TrimSpace(req.MessageDigestHex) == "" {
		return fmt.Errorf("message_digest_hex is required")
	}
	_, err := rbtypes.SelectedParticipants(req.Session.Participants, req.SignerIndexes)
	return err
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

func isExternalParticipant(participant rbtypes.Participant) bool {
	switch participant.ParticipantType {
	case rbtypes.ParticipantServer, rbtypes.ParticipantMobile:
		return true
	default:
		return false
	}
}
