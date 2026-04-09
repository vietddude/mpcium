package sdkflow

import (
	"context"
	"encoding/json"
	"fmt"
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
	keygenBroker messaging.MessageBroker
	signBroker   messaging.MessageBroker
	resultQueue  messaging.MessageQueue
	clientID     string
}

func NewClient(opts ClientOptions) Client {
	if opts.NatsConn == nil {
		logger.Fatal("NATS connection is required", nil)
	}
	if err := validateClientID(opts.ClientID); err != nil {
		logger.Fatal("Invalid client ID", err)
	}

	keygenBroker, err := messaging.NewJetStreamBroker(context.Background(), opts.NatsConn, KeygenRequestStream, []string{
		KeygenRequestTopic(),
	})
	if err != nil {
		logger.Fatal("Failed to create sdkflow keygen broker", err)
	}
	signBroker, err := messaging.NewJetStreamBroker(context.Background(), opts.NatsConn, SignRequestStream, []string{
		SignRequestTopic(),
	})
	if err != nil {
		logger.Fatal("Failed to create sdkflow sign broker", err)
	}
	mqManager := messaging.NewNATsMessageQueueManager("mpc_sdkflow_results", ResultStreamSubjects(), opts.NatsConn)
	resultQueue := mqManager.NewMessageQueue(resultConsumerName(opts.ClientID), "mpc.sdkflow.>")

	return &client{
		keygenBroker: keygenBroker,
		signBroker:   signBroker,
		resultQueue:  resultQueue,
		clientID:     opts.ClientID,
	}
}

func (c *client) Close() {
	if c.resultQueue != nil {
		c.resultQueue.Close()
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
	for _, participant := range req.Session.Participants {
		localReq := req
		localReq.Session.LocalParticipantID = participant.ID
		payload, err := json.Marshal(localReq)
		if err != nil {
			return err
		}
		if err := c.keygenBroker.PublishMessage(context.Background(), KeygenRequestSubject(participant.ID), payload, c.requestHeaders()); err != nil {
			return fmt.Errorf("publish keygen request for %s: %w", participant.ID, err)
		}
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
	for _, participant := range recipients {
		localReq := req
		localReq.Session.LocalParticipantID = participant.ID
		payload, err := json.Marshal(localReq)
		if err != nil {
			return err
		}
		if err := c.signBroker.PublishMessage(context.Background(), SignRequestSubject(participant.ID), payload, c.requestHeaders()); err != nil {
			return fmt.Errorf("publish sign request for %s: %w", participant.ID, err)
		}
	}
	return nil
}

func (c *client) OnKeygenResult(callback func(result KeygenResult)) error {
	return c.resultQueue.Dequeue(KeygenResultSubscriptionSubject(c.clientID), func(message []byte) error {
		var result KeygenResult
		if err := json.Unmarshal(message, &result); err != nil {
			return err
		}
		callback(result)
		return nil
	})
}

func (c *client) OnSignResult(callback func(result SignResult)) error {
	return c.resultQueue.Dequeue(SignResultSubscriptionSubject(c.clientID), func(message []byte) error {
		var result SignResult
		if err := json.Unmarshal(message, &result); err != nil {
			return err
		}
		callback(result)
		return nil
	})
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
		return "mpc_sdkflow_results"
	}
	return "mpc_sdkflow_results." + clientID
}

func validateKeygenRequest(req KeygenRequest) error {
	if strings.TrimSpace(req.Session.SessionID) == "" {
		return fmt.Errorf("session.session_id is required")
	}
	if len(req.Session.Participants) == 0 {
		return fmt.Errorf("session.participants are required")
	}
	if strings.TrimSpace(req.Session.Protocol) == "" {
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

func selectedParticipants(participants []Participant, signerIndexes []uint16) ([]Participant, error) {
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
