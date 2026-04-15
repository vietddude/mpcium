package sessiontransport

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/fystack/mpcium-sdk/secure"
	"github.com/nats-io/nats.go"
)

type Payload struct {
	SessionID    string         `json:"session_id"`
	WalletID     string         `json:"wallet_id"`
	Protocol     string         `json:"protocol,omitempty"`
	Operation    string         `json:"operation,omitempty"`
	SenderID     string         `json:"sender_id"`
	RecipientIDs []string       `json:"recipient_ids,omitempty"`
	Message      secure.Message `json:"message,omitempty"`
}

func (p Payload) Validate() error {
	if strings.TrimSpace(p.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if strings.TrimSpace(p.WalletID) == "" {
		return errors.New("wallet_id is required")
	}
	if strings.TrimSpace(p.SenderID) == "" {
		return errors.New("sender_id is required")
	}
	if strings.TrimSpace(string(p.Message.Type)) == "" {
		return errors.New("message.type is required")
	}
	return nil
}

type Delivery struct {
	Payload Payload
	Err     error
}

// Subscription is the read side of the transport.
// The session runner only cares about a stream of decoded payloads, not raw NATS messages.
type Subscription interface {
	Messages() <-chan Delivery
	Close() error
}

// Transport is the write/read abstraction used by the session layer.
// Current implementation uses NATS underneath, but the session package only depends on this interface.
type Transport interface {
	Subscribe(subjects []string) (Subscription, error)
	Publish(subject string, payload Payload) error
}

type payloadCodec interface {
	Marshal(Payload) ([]byte, error)
	Unmarshal([]byte) (Payload, error)
}

// NATSSessionEnvelopeTransport is the concrete transport used by relaybridge runtime.
// It multiplexes all session traffic through NATS.
type NATSSessionEnvelopeTransport struct {
	nc *nats.Conn
}

// natsSessionEnvelopeSubscription fans multiple NATS subscriptions into one decoded channel.
type natsSessionEnvelopeSubscription struct {
	rawCh  chan *nats.Msg
	outCh  chan Delivery
	done   chan struct{}
	subs   []*nats.Subscription
	once   sync.Once
	closed chan struct{}
}

// NewNATS returns the default session transport implementation used by internal nodes.
func NewNATS(nc *nats.Conn) Transport {
	return &NATSSessionEnvelopeTransport{nc: nc}
}

// Subscribe attaches one shared output channel to every provided subject.
// This lets the session runner listen to both direct NATS traffic and relay inbound traffic
// with one receive loop.
func (t *NATSSessionEnvelopeTransport) Subscribe(subjects []string) (Subscription, error) {
	if t == nil || t.nc == nil {
		return nil, errors.New("nats session transport requires a connection")
	}
	subscription := &natsSessionEnvelopeSubscription{
		rawCh:  make(chan *nats.Msg, 256),
		outCh:  make(chan Delivery, 256),
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

// Publish encodes the payload then publishes it to the target subject.
// Payload format is identical across direct and relay subjects.
func (t *NATSSessionEnvelopeTransport) Publish(subject string, payload Payload) error {
	if t == nil || t.nc == nil {
		return errors.New("nats session transport requires a connection")
	}
	blob, err := payloadCodecForSubject(subject).Marshal(payload)
	if err != nil {
		return err
	}
	return t.nc.Publish(subject, blob)
}

func (s *natsSessionEnvelopeSubscription) Messages() <-chan Delivery {
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

// forward converts raw NATS messages into decoded payloads.
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
			payload, err := payloadCodecForSubject(msg.Subject).Unmarshal(msg.Data)
			select {
			case <-s.done:
				return
			case s.outCh <- Delivery{Payload: payload, Err: err}:
			}
		}
	}
}

type directPayloadCodec struct{}

func payloadCodecForSubject(_ string) payloadCodec { return directPayloadCodec{} }

// directPayloadCodec keeps the full session payload as-is.
func (directPayloadCodec) Marshal(payload Payload) ([]byte, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

func (directPayloadCodec) Unmarshal(data []byte) (Payload, error) {
	var payload Payload
	err := json.Unmarshal(data, &payload)
	return payload, err
}
