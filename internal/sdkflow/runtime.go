package sdkflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	resultJS     jetstream.JetStream
	keygenSub    messaging.MessageSubscription
	signSub      messaging.MessageSubscription
}

func NewRuntime(ctx context.Context, cfg Config) (*Runtime, error) {
	service, err := NewService(cfg)
	if err != nil {
		return nil, err
	}

	keygenBroker, err := messaging.NewJetStreamBroker(
		ctx,
		service.natsConn,
		KeygenRequestStream,
		[]string{KeygenRequestTopic()},
		messaging.WithMaxAckPending(maxOrDefault(cfg.Consumer.MaxConcurrentKeygen, 2)),
	)
	if err != nil {
		_ = service.Close()
		return nil, err
	}

	signBroker, err := messaging.NewJetStreamBroker(
		ctx,
		service.natsConn,
		SignRequestStream,
		[]string{SignRequestTopic()},
		messaging.WithMaxAckPending(maxOrDefault(cfg.Consumer.MaxConcurrentSign, 4)),
	)
	if err != nil {
		_ = keygenBroker.Close()
		_ = service.Close()
		return nil, err
	}

	resultJS, err := newResultJetStream(service.natsConn)
	if err != nil {
		_ = signBroker.Close()
		_ = keygenBroker.Close()
		_ = service.Close()
		return nil, err
	}
	return &Runtime{
		cfg:          cfg,
		service:      service,
		keygenBroker: keygenBroker,
		signBroker:   signBroker,
		resultJS:     resultJS,
	}, nil
}

func (r *Runtime) Close() error {
	if r.keygenSub != nil {
		_ = r.keygenSub.Unsubscribe()
	}
	if r.signSub != nil {
		_ = r.signSub.Unsubscribe()
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
	keygenSub, err := r.keygenBroker.CreateSubscription(
		ctx,
		KeygenConsumerStream+"."+r.cfg.Runtime.ParticipantID,
		KeygenRequestFilterSubject(r.cfg.Runtime.ParticipantID),
		r.handleKeygen,
	)
	if err != nil {
		return err
	}
	r.keygenSub = keygenSub

	signSub, err := r.signBroker.CreateSubscription(
		ctx,
		SignConsumerStream+"."+r.cfg.Runtime.ParticipantID,
		SignRequestFilterSubject(r.cfg.Runtime.ParticipantID),
		r.handleSign,
	)
	if err != nil {
		return err
	}
	r.signSub = signSub

	logger.Info(
		"SDK flow runtime started",
		"participant_id", r.cfg.Runtime.ParticipantID,
		"keygen_subject", KeygenRequestFilterSubject(r.cfg.Runtime.ParticipantID),
		"sign_subject", SignRequestFilterSubject(r.cfg.Runtime.ParticipantID),
	)
	<-ctx.Done()
	return nil
}

func (r *Runtime) handleKeygen(msg jetstream.Msg) {
	target, err := ParseDirectRequestSubject(msg.Subject())
	if err != nil {
		logger.Error("Failed to parse sdkflow keygen request subject", err, "subject", msg.Subject())
		_ = msg.Ack()
		return
	}

	var req KeygenRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		logger.Error("Failed to decode sdkflow keygen request", err)
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if err := applyRequestTarget(&req.Session, target); err != nil {
		logger.Error("Invalid sdkflow keygen request target", err, "subject", msg.Subject())
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if !r.shouldHandleKeygen(req.Session.Participants) {
		logger.Info(
			"SDK flow runtime ignored keygen request",
			"participant_id", r.cfg.Runtime.ParticipantID,
			"session_id", req.Session.SessionID,
			"reason", "runtime participant is not a request participant",
		)
		_ = msg.Ack()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout(r.cfg))
	defer cancel()
	result, err := r.service.RunKeygen(ctx, req)
	if err != nil {
		logger.Error(
			"SDK flow runtime keygen failed",
			err,
			"participant_id", r.cfg.Runtime.ParticipantID,
			"subject", msg.Subject(),
			"session_id", req.Session.SessionID,
			"wallet_id", req.Session.WalletID,
		)
		r.publishKeygenError(msg, req, err)
		_ = msg.Ack()
		return
	}

	if r.shouldReportKeygen(req.Session.Participants) {
		if err := r.publishKeygenResult(msg, *result); err != nil {
			logger.Error("Failed to publish sdkflow keygen result", err)
			_ = msg.Nak()
			return
		}
	}
	_ = msg.Ack()
}

func (r *Runtime) handleSign(msg jetstream.Msg) {
	target, err := ParseDirectRequestSubject(msg.Subject())
	if err != nil {
		logger.Error("Failed to parse sdkflow sign request subject", err, "subject", msg.Subject())
		_ = msg.Ack()
		return
	}

	var req SignRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		logger.Error("Failed to decode sdkflow sign request", err)
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if err := applyRequestTarget(&req.Session, target); err != nil {
		logger.Error("Invalid sdkflow sign request target", err, "subject", msg.Subject())
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}

	recipients, err := selectedParticipants(req.Session.Participants, req.SignerIndexes)
	if err != nil {
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}
	if !r.shouldHandleSign(recipients) {
		logger.Info(
			"SDK flow runtime ignored sign request",
			"participant_id", r.cfg.Runtime.ParticipantID,
			"session_id", req.Session.SessionID,
			"reason", "runtime participant is not a signer target",
		)
		_ = msg.Ack()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout(r.cfg))
	defer cancel()
	result, err := r.service.RunSign(ctx, req)
	if err != nil {
		logger.Error(
			"SDK flow runtime sign failed",
			err,
			"participant_id", r.cfg.Runtime.ParticipantID,
			"subject", msg.Subject(),
			"session_id", req.Session.SessionID,
			"wallet_id", req.Session.WalletID,
		)
		r.publishSignError(msg, req, err)
		_ = msg.Ack()
		return
	}

	if r.shouldReportSign(recipients) {
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
	return publishResult(
		r.resultJS,
		KeygenResultSubject(clientID, result.SessionID),
		payload,
		"sdkflow:keygen:"+result.SessionID,
	)
}

func (r *Runtime) publishKeygenError(msg jetstream.Msg, req KeygenRequest, err error) {
	result := KeygenResult{
		SessionID:   req.Session.SessionID,
		WalletID:    req.Session.WalletID,
		Protocol:    string(req.Session.Protocol),
		ResultType:  event.ResultTypeError,
		ErrorReason: err.Error(),
		ErrorCode:   event.GetErrorCodeFromError(err),
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
	return publishResult(
		r.resultJS,
		SignResultSubject(clientID, result.SessionID),
		payload,
		"sdkflow:sign:"+result.SessionID,
	)
}

func (r *Runtime) publishSignError(msg jetstream.Msg, req SignRequest, err error) {
	result := SignResult{
		SessionID:   req.Session.SessionID,
		WalletID:    req.Session.WalletID,
		Protocol:    string(req.Session.Protocol),
		ResultType:  event.ResultTypeError,
		ErrorReason: err.Error(),
		ErrorCode:   event.GetErrorCodeFromError(err),
	}
	if publishErr := r.publishSignResult(msg, result); publishErr != nil {
		logger.Error("Failed to publish sdkflow sign error result", publishErr)
	}
}

func (r *Runtime) shouldHandleKeygen(participants []Participant) bool {
	for _, participant := range participants {
		if participant.ID == r.cfg.Runtime.ParticipantID {
			return true
		}
	}
	return false
}

func (r *Runtime) shouldHandleSign(recipients []Participant) bool {
	for _, participant := range recipients {
		if participant.ID == r.cfg.Runtime.ParticipantID {
			return true
		}
	}
	return false
}

func (r *Runtime) shouldReportKeygen(participants []Participant) bool {
	return preferredReporter(participants) == r.cfg.Runtime.ParticipantID
}

func (r *Runtime) shouldReportSign(recipients []Participant) bool {
	return preferredReporter(recipients) == r.cfg.Runtime.ParticipantID
}

func requestTimeout(cfg Config) time.Duration {
	return parseDurationOrDefault(cfg.Runtime.RequestTimeout, 45*time.Second)
}

func newResultJetStream(nc *nats.Conn) (jetstream.JetStream, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	_, err = js.CreateOrUpdateStream(context.Background(), jetstream.StreamConfig{
		Name:        resultStreamName,
		Description: "Stream for " + resultStreamName,
		Subjects:    ResultStreamSubjects(),
		MaxBytes:    100_000_000,
		Storage:     jetstream.FileStorage,
		Retention:   jetstream.WorkQueuePolicy,
	})
	if err != nil {
		return nil, err
	}
	return js, nil
}

func publishResult(js jetstream.JetStream, subject string, payload []byte, idempotencyKey string) error {
	if js == nil {
		return fmt.Errorf("result jetstream context is required")
	}
	msg := &nats.Msg{
		Subject: subject,
		Data:    payload,
	}
	if idempotencyKey != "" {
		msg.Header = nats.Header{}
		msg.Header.Set("Nats-Msg-Id", idempotencyKey)
	}
	_, err := js.PublishMsg(context.Background(), msg)
	return err
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
	target, err := ParseDirectRequestSubject(subject)
	if err != nil {
		return err
	}
	if target.ParticipantID != r.cfg.Runtime.ParticipantID {
		return fmt.Errorf(
			"unexpected request participant %q for runtime participant %q",
			target.ParticipantID,
			r.cfg.Runtime.ParticipantID,
		)
	}
	return nil
}

func preferredReporter(participants []Participant) string {
	if len(participants) == 0 {
		return ""
	}
	for _, participant := range participants {
		if participant.ParticipantType == ParticipantNode || participant.ParticipantType == "" {
			return participant.ID
		}
	}
	return participants[0].ID
}

func applyRequestTarget(session *SessionContext, target requestTarget) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	if strings.TrimSpace(session.SessionID) == "" {
		session.SessionID = target.SessionID
	} else if session.SessionID != target.SessionID {
		return fmt.Errorf("session.session_id %q does not match request target %q", session.SessionID, target.SessionID)
	}
	if strings.TrimSpace(session.WalletID) == "" {
		session.WalletID = target.WalletID
	} else if session.WalletID != target.WalletID {
		return fmt.Errorf("session.wallet_id %q does not match request target %q", session.WalletID, target.WalletID)
	}
	session.Operation = target.Operation
	session.LocalParticipantID = target.ParticipantID
	return nil
}
