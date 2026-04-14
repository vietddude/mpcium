package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/fystack/mpcium-sdk/mpcore"
	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/secure"
	relayprotocol "github.com/fystack/mpcium/internal/relay/protocol"
	"github.com/nats-io/nats.go"
)

type SessionEnvelopeMessage struct {
	Envelope protocol.Envelope
	Err      error
}

// SessionEnvelopeSubscription is the read side of the transport.
// The session runner only cares about a stream of decoded envelopes, not raw NATS messages.
type SessionEnvelopeSubscription interface {
	Messages() <-chan SessionEnvelopeMessage
	Close() error
}

// SessionEnvelopeTransport is the write/read abstraction used by the session layer.
// Current implementation uses NATS underneath, but the session package only depends on this interface.
type SessionEnvelopeTransport interface {
	Subscribe(subjects []string) (SessionEnvelopeSubscription, error)
	Publish(subject string, envelope protocol.Envelope) error
}

// sessionEnvelopeCodec lets us switch wire format by subject namespace:
// direct internal subjects use raw protocol.Envelope JSON,
// relay subjects use the relayBridgeEnvelope compatibility shape.
type sessionEnvelopeCodec interface {
	Marshal(protocol.Envelope) ([]byte, error)
	Unmarshal([]byte) (protocol.Envelope, error)
}

// NATSSessionEnvelopeTransport is the concrete transport used by relaybridge runtime.
// It multiplexes all session traffic through NATS, and picks codec based on subject prefix.
type NATSSessionEnvelopeTransport struct {
	nc *nats.Conn
}

// natsSessionEnvelopeSubscription fans multiple NATS subscriptions into one decoded channel.
type natsSessionEnvelopeSubscription struct {
	rawCh  chan *nats.Msg
	outCh  chan SessionEnvelopeMessage
	done   chan struct{}
	subs   []*nats.Subscription
	once   sync.Once
	closed chan struct{}
}

// NewNATS returns the default session transport implementation used by internal nodes.
func NewNATS(nc *nats.Conn) SessionEnvelopeTransport {
	return &NATSSessionEnvelopeTransport{nc: nc}
}

// Subscribe attaches one shared output channel to every provided subject.
// This lets the session runner listen to both direct NATS traffic and relay inbound traffic
// with one receive loop.
func (t *NATSSessionEnvelopeTransport) Subscribe(subjects []string) (SessionEnvelopeSubscription, error) {
	if t == nil || t.nc == nil {
		return nil, errors.New("nats session transport requires a connection")
	}
	subscription := &natsSessionEnvelopeSubscription{
		rawCh:  make(chan *nats.Msg, 256),
		outCh:  make(chan SessionEnvelopeMessage, 256),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	for _, subject := range subjects {
		sub, err := t.nc.ChanSubscribe(subject, subscription.rawCh)
		if err != nil {
			_ = subscription.Close()
			return nil, err
		}
		subscription.subs = append(subscription.subs, sub)
	}
	if err := t.nc.Flush(); err != nil {
		_ = subscription.Close()
		return nil, err
	}
	go subscription.forward()
	return subscription, nil
}

// Publish encodes the envelope according to the target subject namespace, then publishes it.
// Direct internal subjects keep the SDK envelope as-is.
// Relay subjects are converted into the relay-compatible JSON payload.
func (t *NATSSessionEnvelopeTransport) Publish(subject string, envelope protocol.Envelope) error {
	if t == nil || t.nc == nil {
		return errors.New("nats session transport requires a connection")
	}
	payload, err := sessionCodecForSubject(subject).Marshal(envelope)
	if err != nil {
		return err
	}
	return t.nc.Publish(subject, payload)
}

func (s *natsSessionEnvelopeSubscription) Messages() <-chan SessionEnvelopeMessage {
	return s.outCh
}

func (s *natsSessionEnvelopeSubscription) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.once.Do(func() {
		close(s.done)
		for _, sub := range s.subs {
			if unsubErr := sub.Unsubscribe(); unsubErr != nil && err == nil {
				err = unsubErr
			}
		}
		<-s.closed
	})
	return err
}

// forward converts raw NATS messages into decoded session envelopes.
func (s *natsSessionEnvelopeSubscription) forward() {
	defer close(s.closed)
	defer close(s.outCh)
	for {
		select {
		case <-s.done:
			return
		case msg := <-s.rawCh:
			if msg == nil {
				continue
			}
			envelope, err := sessionCodecForSubject(msg.Subject).Unmarshal(msg.Data)
			select {
			case <-s.done:
				return
			case s.outCh <- SessionEnvelopeMessage{
				Envelope: envelope,
				Err:      err,
			}:
			}
		}
	}
}

// relayBridgeEnvelope is the reduced wire format that travels on relay subjects.
// It exists because relay/cosigner traffic does not carry the full protocol.Envelope shape.
// Instead we encode the session metadata plus either:
// - kind=ready: peer is ready, no secure payload
// - kind=secure: secure session message payload present
type relayBridgeEnvelope struct {
	SessionID string          `json:"session_id"`
	WalletID  string          `json:"wallet_id"`
	Protocol  string          `json:"protocol,omitempty"`
	Operation string          `json:"operation,omitempty"`
	SenderID  string          `json:"sender_id"`
	Kind      string          `json:"kind"`
	Message   *secure.Message `json:"message,omitempty"`
	SentAt    string          `json:"sent_at,omitempty"`
}

type directSessionEnvelopeCodec struct{}

type relayBridgeEnvelopeCodec struct{}

// sessionCodecForSubject is the switch that makes one transport support two wire formats.
// Anything in relay namespaces uses relayBridgeEnvelopeCodec.
// Everything else is treated as direct internal NATS traffic and uses raw envelope JSON.
func sessionCodecForSubject(subject string) sessionEnvelopeCodec {
	switch {
	case strings.HasPrefix(subject, relayprotocol.OutboundNATSSubjectPrefix+"."),
		strings.HasPrefix(subject, relayprotocol.InboundNATSSubjectPrefix+"."):
		return relayBridgeEnvelopeCodec{}
	default:
		return directSessionEnvelopeCodec{}
	}
}

// directSessionEnvelopeCodec keeps the full protocol.Envelope payload for internal node-to-node traffic.
func (directSessionEnvelopeCodec) Marshal(envelope protocol.Envelope) ([]byte, error) {
	if !IsReadyEnvelope(envelope) {
		if err := envelope.Validate(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(envelope)
}

func (directSessionEnvelopeCodec) Unmarshal(payload []byte) (protocol.Envelope, error) {
	var envelope protocol.Envelope
	err := json.Unmarshal(payload, &envelope)
	return envelope, err
}

// relayBridgeEnvelopeCodec converts between protocol.Envelope and relayBridgeEnvelope.
// This is the compatibility boundary between internal relaybridge runtime and relay/cosigner transport.
func (relayBridgeEnvelopeCodec) Marshal(envelope protocol.Envelope) ([]byte, error) {
	return marshalRelayBridgeEnvelope(envelope)
}

func (relayBridgeEnvelopeCodec) Unmarshal(payload []byte) (protocol.Envelope, error) {
	return unmarshalRelayBridgeEnvelope(payload)
}

// marshalRelayBridgeEnvelope drops the outer SDK envelope wrapper and serializes only the
// relay-relevant fields. A ready envelope becomes {"kind":"ready"}, while a normal secure
// message becomes {"kind":"secure","message":...}.
func marshalRelayBridgeEnvelope(envelope protocol.Envelope) ([]byte, error) {
	if envelope.Type != protocol.EnvelopeTypeSession || envelope.Session == nil {
		return nil, errors.New("relay bridge transport requires a session envelope")
	}
	bridge := relayBridgeEnvelope{
		SessionID: envelope.Session.SessionID,
		WalletID:  envelope.Session.WalletID,
		Protocol:  envelope.Session.Protocol,
		Operation: envelope.Session.Operation,
		SenderID:  envelope.Session.SenderID,
		SentAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if IsReadyEnvelope(envelope) {
		bridge.Kind = "ready"
	} else {
		bridge.Kind = "secure"
		message := envelope.Session.Message
		bridge.Message = &message
	}
	return json.Marshal(bridge)
}

// unmarshalRelayBridgeEnvelope reconstructs a protocol.Envelope from relay payload.
// Relay payload does not carry recipient IDs, so that field is left empty on decode.
func unmarshalRelayBridgeEnvelope(payload []byte) (protocol.Envelope, error) {
	var bridge relayBridgeEnvelope
	if err := json.Unmarshal(payload, &bridge); err != nil {
		return protocol.Envelope{}, err
	}
	session := &protocol.SessionPayload{
		SessionID:    strings.TrimSpace(bridge.SessionID),
		WalletID:     strings.TrimSpace(bridge.WalletID),
		KeyType:      mpcore.NormalizeKeyType(strings.TrimSpace(bridge.Protocol)),
		Protocol:     strings.TrimSpace(bridge.Protocol),
		Operation:    strings.TrimSpace(bridge.Operation),
		SenderID:     strings.TrimSpace(bridge.SenderID),
		RecipientIDs: nil,
	}
	if bridge.Kind == "secure" && bridge.Message != nil {
		session.Message = *bridge.Message
	}
	return protocol.Envelope{
		Version: protocol.EnvelopeVersion,
		Type:    protocol.EnvelopeTypeSession,
		Session: session,
	}, nil
}

// IsReadyEnvelope identifies the handshake envelope used before the secure MPC rounds start.
// In practice it is a session envelope with no secure message payload.
func IsReadyEnvelope(env protocol.Envelope) bool {
	return env.Type == protocol.EnvelopeTypeSession &&
		env.Session != nil &&
		env.Session.Message.Type == ""
}
