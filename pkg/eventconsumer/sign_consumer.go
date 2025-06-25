package eventconsumer

import (
	"context"
	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// Maximum time to wait for a signing response.
	signingResponseTimeout = 30 * time.Second
	// How often to poll for the reply message.
	signingPollingInterval = 500 * time.Millisecond
)

// SigningConsumer represents a consumer that processes signing events.
type SigningConsumer interface {
	// Run starts the consumer and blocks until the provided context is canceled.
	Run(ctx context.Context) error
	// Close performs a graceful shutdown of the consumer.
	Close() error
}

// signingConsumer implements SigningConsumer.
type signingConsumer struct {
	natsConn *nats.Conn
	pubsub   messaging.PubSub
	jsPubsub messaging.StreamPubsub

	// jsSub holds the JetStream subscription, so it can be cleaned up during Close().
	jsSub messaging.Subscription
}

// NewSigningConsumer returns a new instance of SigningConsumer.
func NewSigningConsumer(
	natsConn *nats.Conn,
	jsPubsub messaging.StreamPubsub,
	pubsub messaging.PubSub,
) SigningConsumer {
	return &signingConsumer{
		natsConn: natsConn,
		pubsub:   pubsub,
		jsPubsub: jsPubsub,
	}
}

// Run subscribes to signing events and processes them until the context is canceled.
func (sc *signingConsumer) Run(ctx context.Context) error {
	sub, err := sc.jsPubsub.Subscribe(
		event.SigningConsumerStream,
		event.SigningRequestEventTopic,
		sc.handleSigningEvent,
	)
	if err != nil {
		return fmt.Errorf("failed to subscribe to signing events: %w", err)
	}
	sc.jsSub = sub
	logger.Info("SigningConsumer: Subscribed to signing events")

	// Block until context cancellation.
	<-ctx.Done()

	// When context is canceled, close subscription.
	return sc.Close()
}

// The handleSigningEvent function in sign_consumer.go acts as a bridge between the JetStream-based event queue and the MPC (Multi-Party Computation) signing system
// Creates a reply channel: It generates a unique inbox address using nats.NewInbox() to receive the signing response.
// Sets up response handling: It creates a synchronous subscription to listen for replies on this inbox.
// Forwards the signing request: It publishes the original signing event data to the MPCSigningEventTopic with the reply inbox attached, which triggers the MPC signing process.
// Polls for completion: It enters a polling loop that checks for a reply message, continuing until either:
// A reply is received (successful signing)
// An error occurs (failed signing)
// The timeout is reached (30 seconds)
// Completes the transaction: It either acknowledges (Ack) the message if signing was successful or negatively acknowledges (Nak) it if there was a timeout or error.
// MPC Session Interaction
// The signing consumer doesn't directly interact with MPC sessions. Instead:
// It publishes the signing request to the MPCSigningEventTopic, which is consumed by the eventconsumer.consumeTxSigningEvent handler.
// This handler creates the appropriate signing session (SigningSession for ECDSA or EDDSASigningSession for EdDSA) via the MPC node's creation methods.
// The MPC signing sessions manage the distributed cryptographic operations across multiple nodes, handling message routing, party updates, and signature verification.
// When signing completes, the session publishes the result to a queue and calls the onSuccess callback, which sends a reply to the inbox that the SigningConsumer is monitoring.
// The reply signals completion, allowing the SigningConsumer to acknowledge the original message.
func (sc *signingConsumer) handleSigningEvent(msg jetstream.Msg) {
	// Create a reply inbox to receive the signing event response.
	replyInbox := nats.NewInbox()

	// Use a synchronous subscription for the reply inbox.
	replySub, err := sc.natsConn.SubscribeSync(replyInbox)
	if err != nil {
		logger.Error("SigningConsumer: Failed to subscribe to reply inbox", err)
		_ = msg.Nak()
		return
	}
	defer func() {
		if err := replySub.Unsubscribe(); err != nil {
			logger.Warn("SigningConsumer: Failed to unsubscribe from reply inbox", err)
		}
	}()

	// Publish the signing event with the reply inbox.
	if err := sc.pubsub.PublishWithReply(event.MPCSigningEventTopic, replyInbox, msg.Data()); err != nil {
		logger.Error("SigningConsumer: Failed to publish signing event with reply", err)
		_ = msg.Nak()
		return
	}

	// Poll for the reply message until timeout.
	deadline := time.Now().Add(signingResponseTimeout)
	for time.Now().Before(deadline) {
		replyMsg, err := replySub.NextMsg(signingPollingInterval)
		if err != nil {
			// If timeout occurs, continue trying.
			if err == nats.ErrTimeout {
				continue
			}
			logger.Error("SigningConsumer: Error receiving reply message", err)
			break
		}
		if replyMsg != nil {
			logger.Info("SigningConsumer: Completed signing event; reply received")
			if ackErr := msg.Ack(); ackErr != nil {
				logger.Error("SigningConsumer: ACK failed", ackErr)
			}
			return
		}
	}

	logger.Warn("SigningConsumer: Timeout waiting for signing event response")
	_ = msg.Nak()
}

// Close unsubscribes from the JetStream subject and cleans up resources.
func (sc *signingConsumer) Close() error {
	if sc.jsSub != nil {
		if err := sc.jsSub.Unsubscribe(); err != nil {
			logger.Error("SigningConsumer: Failed to unsubscribe from JetStream", err)
			return err
		}
		logger.Info("SigningConsumer: Unsubscribed from JetStream")
	}
	return nil
}
