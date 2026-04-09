package sdkflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type Runtime struct {
	cfg          Config
	service      *Service
	keygenBroker messaging.MessageBroker
	signBroker   messaging.MessageBroker
	resultQueue  messaging.MessageQueue
	keygenSub    messaging.MessageSubscription
	signSub      messaging.MessageSubscription
}

func NewRuntime(ctx context.Context, cfg Config) (*Runtime, error) {
	service, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	keygenBroker, err := messaging.NewJetStreamBroker(ctx, service.natsConn, KeygenRequestStream, []string{
		KeygenRequestTopic(),
	}, messaging.WithMaxAckPending(maxOrDefault(cfg.Consumer.MaxConcurrentKeygen, 2)))
	if err != nil {
		_ = service.Close()
		return nil, err
	}
	signBroker, err := messaging.NewJetStreamBroker(ctx, service.natsConn, SignRequestStream, []string{
		SignRequestTopic(),
	}, messaging.WithMaxAckPending(maxOrDefault(cfg.Consumer.MaxConcurrentSign, 4)))
	if err != nil {
		_ = keygenBroker.Close()
		_ = service.Close()
		return nil, err
	}
	mqManager := messaging.NewNATsMessageQueueManager("mpc_sdkflow_results", ResultStreamSubjects(), service.natsConn)
	resultQueue := mqManager.NewMessageQueue("mpc_sdkflow_results", "mpc.sdkflow.>")
	return &Runtime{
		cfg:          cfg,
		service:      service,
		keygenBroker: keygenBroker,
		signBroker:   signBroker,
		resultQueue:  resultQueue,
	}, nil
}

func (r *Runtime) Close() error {
	if r.keygenSub != nil {
		_ = r.keygenSub.Unsubscribe()
	}
	if r.signSub != nil {
		_ = r.signSub.Unsubscribe()
	}
	if r.resultQueue != nil {
		r.resultQueue.Close()
	}
	if r.keygenBroker != nil {
		_ = r.keygenBroker.Close()
	}
	if r.signBroker != nil {
		_ = r.signBroker.Close()
	}
	if r.service != nil {
		return r.service.Close()
	}
	return nil
}

func (r *Runtime) Start(ctx context.Context) error {
	keygenSub, err := r.keygenBroker.CreateSubscription(ctx, KeygenConsumerStream+"."+r.cfg.Runtime.ParticipantID, KeygenRequestSubject(r.cfg.Runtime.ParticipantID), r.handleKeygen)
	if err != nil {
		return err
	}
	r.keygenSub = keygenSub

	signSub, err := r.signBroker.CreateSubscription(ctx, SignConsumerStream+"."+r.cfg.Runtime.ParticipantID, SignRequestSubject(r.cfg.Runtime.ParticipantID), r.handleSign)
	if err != nil {
		return err
	}
	r.signSub = signSub

	logger.Info("SDK flow runtime started", "participant_id", r.cfg.Runtime.ParticipantID, "keygen_subject", KeygenRequestSubject(r.cfg.Runtime.ParticipantID), "sign_subject", SignRequestSubject(r.cfg.Runtime.ParticipantID))
	<-ctx.Done()
	return nil
}

func (r *Runtime) handleKeygen(msg jetstream.Msg) {
	var req KeygenRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout(r.cfg))
	defer cancel()
	result, err := r.service.RunKeygen(ctx, req)
	if err != nil {
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if r.shouldReport(req.Session.Participants, req.Session.LocalParticipantID) {
		if err := r.publishKeygenResult(msg, *result); err != nil {
			logger.Error("Failed to publish sdkflow keygen result", err)
			_ = msg.Nak()
			return
		}
	}
	_ = msg.Ack()
}

func (r *Runtime) handleSign(msg jetstream.Msg) {
	var req SignRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout(r.cfg))
	defer cancel()
	result, err := r.service.RunSign(ctx, req)
	if err != nil {
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if r.shouldReport(req.Session.Participants, req.Session.LocalParticipantID) {
		if err := r.publishSignResult(msg, *result); err != nil {
			logger.Error("Failed to publish sdkflow sign result", err)
			_ = msg.Nak()
			return
		}
	}
	_ = msg.Ack()
}

func (r *Runtime) publishKeygenResult(msg jetstream.Msg, result KeygenResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	clientID := msg.Headers().Get(event.ClientIDHeader)
	return r.resultQueue.Enqueue(KeygenResultSubject(clientID, result.SessionID), payload, &messaging.EnqueueOptions{
		IdempotententKey: "sdkflow:keygen:" + result.SessionID,
	})
}

func (r *Runtime) publishKeygenError(msg jetstream.Msg, req KeygenRequest, err error) {
	result := KeygenResult{
		SessionID:   req.Session.SessionID,
		WalletID:    req.Session.WalletID,
		KeyID:       req.Session.KeyID,
		Protocol:    req.Session.Protocol,
		ResultType:  event.ResultTypeError,
		ErrorReason: err.Error(),
		ErrorCode:   string(event.GetErrorCodeFromError(err)),
	}
	if publishErr := r.publishKeygenResult(msg, result); publishErr != nil {
		logger.Error("Failed to publish sdkflow keygen error result", publishErr)
	}
}

func (r *Runtime) publishSignResult(msg jetstream.Msg, result SignResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	clientID := msg.Headers().Get(event.ClientIDHeader)
	return r.resultQueue.Enqueue(SignResultSubject(clientID, result.SessionID), payload, &messaging.EnqueueOptions{
		IdempotententKey: "sdkflow:sign:" + result.SessionID,
	})
}

func (r *Runtime) publishSignError(msg jetstream.Msg, req SignRequest, err error) {
	result := SignResult{
		SessionID:   req.Session.SessionID,
		WalletID:    req.Session.WalletID,
		KeyID:       req.Session.KeyID,
		Protocol:    req.Session.Protocol,
		ResultType:  event.ResultTypeError,
		ErrorReason: err.Error(),
		ErrorCode:   string(event.GetErrorCodeFromError(err)),
	}
	if publishErr := r.publishSignResult(msg, result); publishErr != nil {
		logger.Error("Failed to publish sdkflow sign error result", publishErr)
	}
}

func (r *Runtime) shouldReport(participants []Participant, localParticipantID string) bool {
	return len(participants) > 0 && participants[0].ID == localParticipantID
}

func requestTimeout(cfg Config) time.Duration {
	return parseDurationOrDefault(cfg.Runtime.RequestTimeout, 45*time.Second)
}

func maxOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func (r *Runtime) NATSConn() *nats.Conn {
	if r.service == nil {
		return nil
	}
	return r.service.natsConn
}

func (r *Runtime) ValidateRequestTarget(subject string) error {
	expectedKeygen := KeygenRequestSubject(r.cfg.Runtime.ParticipantID)
	expectedSign := SignRequestSubject(r.cfg.Runtime.ParticipantID)
	if subject != expectedKeygen && subject != expectedSign {
		return fmt.Errorf("unexpected request subject %q", subject)
	}
	return nil
}
