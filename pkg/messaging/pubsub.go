package messaging

import (
	"context"
	"strings"
	"time"
	"unicode"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type Subscription interface {
	Unsubscribe() error
}

type PubSub interface {
	Publish(topic string, message []byte) error
	PublishWithReply(ttopic, reply string, data []byte) error
	Subscribe(topic string, handler func(msg *nats.Msg)) (Subscription, error)
}

type natsPubSub struct {
	natsConn *nats.Conn
}

type natsSubscription struct {
	subscription *nats.Subscription
}

type jetstreamSubscription struct {
	consumer jetstream.Consumer
}

func (ns *natsSubscription) Unsubscribe() error {
	return ns.subscription.Unsubscribe()
}

func (js *jetstreamSubscription) Unsubscribe() error {
	return nil
}

func NewNATSPubSub(natsConn *nats.Conn) PubSub {
	return &natsPubSub{natsConn}
}

func (n *natsPubSub) Publish(topic string, message []byte) error {
	logger.Debug("[NATS] Publishing message", "topic", topic)
	return n.natsConn.Publish(topic, message)
}

func (n *natsPubSub) PublishWithReply(topic, reply string, data []byte) error {
	return n.natsConn.PublishMsg(&nats.Msg{
		Subject: topic,
		Reply:   reply,
		Data:    data,
	})
}

func (n *natsPubSub) Subscribe(topic string, handler func(msg *nats.Msg)) (Subscription, error) {
	// TODO: Handle subscription
	// handle more fields in msg
	sub, err := n.natsConn.Subscribe(topic, func(msg *nats.Msg) {
		handler(msg)
	})
	if err != nil {
		return nil, err
	}

	return &natsSubscription{subscription: sub}, nil
}

type StreamPubsub interface {
	Publish(topic string, message []byte) error
	Subscribe(name string, topic string, handler func(msg jetstream.Msg)) (Subscription, error)
}

type StreamPubsubOption func(*streamPubSubConfig)

type streamPubSubConfig struct {
	streamName          string
	subjects            []string
	description         string
	retention           nats.RetentionPolicy
	storage             nats.StorageType
	maxAge              time.Duration
	discard             nats.DiscardPolicy
	ackWait             time.Duration
	maxDeliveryAttempts int
	consumerNamePrefix  string
}

func WithDescription(description string) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.description = description
	}
}

func WithRetention(policy nats.RetentionPolicy) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.retention = policy
	}
}

func WithStorage(storage nats.StorageType) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.storage = storage
	}
}

func WithMaxAge(maxAge time.Duration) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.maxAge = maxAge
	}
}

func WithDiscardPolicy(policy nats.DiscardPolicy) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.discard = policy
	}
}

func WithAckWait(ackWait time.Duration) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.ackWait = ackWait
	}
}

func WithMaxDeliveryAttempts(maxAttempts int) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.maxDeliveryAttempts = maxAttempts
	}
}

func WithConsumerNamePrefix(prefix string) StreamPubsubOption {
	return func(cfg *streamPubSubConfig) {
		cfg.consumerNamePrefix = prefix
	}
}

type jetStreamPubSub struct {
	name   string
	config streamPubSubConfig
	js     jetstream.JetStream
}

func NewJetStreamPubSub(
	natsConn *nats.Conn,
	streamName string,
	subjects []string,
	opts ...StreamPubsubOption,
) (StreamPubsub, error) {
	config := streamPubSubConfig{
		streamName:          streamName,
		subjects:            subjects,
		retention:           nats.InterestPolicy,
		storage:             nats.MemoryStorage,
		discard:             nats.DiscardOld,
		ackWait:             60 * time.Second,
		maxDeliveryAttempts: 3,
		consumerNamePrefix:  "consumer",
	}
	for _, opt := range opts {
		opt(&config)
	}

	js, err := jetstream.New(natsConn)
	if err != nil {
		logger.Fatal("Error creating JetStream context: ", err)
	}

	ctx := context.Background()
	stream, err := js.Stream(ctx, streamName)
	if err != nil {
		logger.Warn("Stream not found, creating new stream", "stream", streamName)
	}
	if stream != nil {
		_, err := stream.Info(ctx)
		if err != nil {
			logger.Fatal("Error getting stream info: ", err)
		}
	}

	_, err = js.CreateOrUpdateStream(context.Background(), jetstream.StreamConfig{
		Name:        streamName,
		Description: "Stream for " + streamName,
		Subjects:    subjects,
		MaxAge:      3 * time.Minute,
	})

	if err != nil {
		logger.Fatal("Error creating JetStream stream: ", err)
	}

	logger.Info("Creating apex NATs Jetstream context successfully!")

	return &jetStreamPubSub{
		name:   streamName,
		config: config,
		js:     js,
	}, nil
}

func (j *jetStreamPubSub) Publish(topic string, message []byte) error {
	_, err := j.js.Publish(context.Background(), topic, message)
	return err
}

func sanitizeConsumerName(name string) string {
	// Replace invalid characters
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ">", "all")
	name = strings.ReplaceAll(name, "*", "any")

	// Ensure it starts with a letter or underscore
	if len(name) > 0 && !unicode.IsLetter(rune(name[0])) && name[0] != '_' {
		name = "_" + name
	}

	return name
}

func (j *jetStreamPubSub) Subscribe(
	name string,
	topic string,
	handler func(msg jetstream.Msg),
) (Subscription, error) {

	logger.Info("Subscribing to topic", sanitizeConsumerName(name), topic)
	consumerConfig := jetstream.ConsumerConfig{
		Name:          sanitizeConsumerName(name),
		Durable:       sanitizeConsumerName(name),
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    4,
		BackOff:       []time.Duration{30 * time.Second, 30 * time.Second, 30 * time.Second},
		DeliverPolicy: jetstream.DeliverAllPolicy, // Deliver all messages
		FilterSubject: topic,
		AckWait:       30 * time.Second, // explicitly set ack wait here
	}

	logger.Info("Creating consumer", "config", consumerConfig, "stream", j.config.streamName)
	consumer, err := j.js.CreateOrUpdateConsumer(
		context.Background(),
		j.config.streamName,
		consumerConfig,
	)

	if err != nil {
		logger.Error("❌ Failed to create or update consumer:", err)
	}

	if consumer != nil {
		logger.Info("Successfully created or updated consumer", "consumer", consumer)
	}

	_, err = consumer.Consume(func(msg jetstream.Msg) {
		logger.Info("Received jetStreamPubSub message", "subject", msg.Data())
		handler(msg)
	})

	if err != nil {
		logger.Error("Failed to consume message:", err)
	}

	return &jetstreamSubscription{consumer: consumer}, nil
}
