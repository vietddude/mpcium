package relay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

const defaultMQTTListenerID = "relay-mqtt"

type Runtime struct {
	cfg         *config.RelayConfig
	mqttServer  *mqtt.Server
	mqttAddress string
	natsConn    *nats.Conn
	natsSub     *nats.Subscription
	redisClient *redis.Client
	presence    PresenceStore
	mapper      TopicMapper
	credentials CredentialStore
	sessions    *SessionRegistry
	mqttHook    *relayHook
}

func NewRuntime(cfg *config.RelayConfig) (*Runtime, error) {
	if err := validateRuntimeConfig(cfg); err != nil {
		return nil, err
	}

	credentials, err := NewStaticCredentialStore(cfg.Auth.Cosigners)
	if err != nil {
		return nil, err
	}

	natsConn, err := connectNATS(cfg.Environment, cfg.NATs)
	if err != nil {
		return nil, err
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		natsConn.Close()
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	caps := mqtt.NewDefaultServerCapabilities()
	caps.RetainAvailable = 0

	mqttServer := mqtt.New(&mqtt.Options{
		Capabilities: caps,
		InlineClient: true,
		Logger:       mqttSilentLogger(),
	})

	listener := listeners.NewTCP(listeners.Config{
		ID:      mqttListenerID(cfg),
		Address: cfg.MQTT.Address,
	})
	if err := mqttServer.AddListener(listener); err != nil {
		natsConn.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("failed to add mqtt listener: %w", err)
	}

	runtime := &Runtime{
		cfg:         cfg,
		mqttServer:  mqttServer,
		mqttAddress: listener.Address(),
		natsConn:    natsConn,
		redisClient: redisClient,
		presence:    NewRedisPresenceStore(redisClient, cfg.Redis.KeyPrefix, cfg.Redis.OnlineTTL),
		mapper:      NewTopicMapper(),
		credentials: credentials,
		sessions:    NewSessionRegistry(),
	}

	runtime.mqttHook = newRelayHook(
		mqttServer,
		runtime.credentials,
		runtime.sessions,
		runtime.presence,
		runtime.mapper,
		natsConn,
		cfg.PresenceEventsEnabled,
	)

	if err := mqttServer.AddHook(runtime.mqttHook, nil); err != nil {
		natsConn.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("failed to add mqtt relay hook: %w", err)
	}

	return runtime, nil
}

func (r *Runtime) Start() error {
	sub, err := r.natsConn.Subscribe(OutboundNATSSubjectPrefix+".>", r.handleOutboundNATSMessage)
	if err != nil {
		return fmt.Errorf("failed to subscribe to outbound relay subjects: %w", err)
	}
	r.natsSub = sub

	if err := r.mqttServer.Serve(); err != nil {
		_ = r.natsSub.Unsubscribe()
		return fmt.Errorf("failed to start mqtt server: %w", err)
	}

	if err := r.natsConn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nats subscriptions: %w", err)
	}

	logger.Info("Relay runtime started", "mqtt_address", r.mqttAddress, "nats_url", r.cfg.NATs.URL, "redis_addr", r.cfg.Redis.Addr)
	return nil
}

func (r *Runtime) Close() error {
	if r.natsSub != nil {
		_ = r.natsSub.Unsubscribe()
	}

	if r.mqttServer != nil {
		if err := r.mqttServer.Close(); err != nil {
			return err
		}
	}

	if r.natsConn != nil && !r.natsConn.IsClosed() {
		if err := r.natsConn.Drain(); err != nil {
			r.natsConn.Close()
		}
	}

	if r.redisClient != nil {
		return r.redisClient.Close()
	}

	return nil
}

func (r *Runtime) MQTTAddress() string {
	return r.mqttAddress
}

func (r *Runtime) handleOutboundNATSMessage(msg *nats.Msg) {
	topic, err := r.mapper.NatsToMQTT(msg.Subject)
	if err != nil {
		logger.Warn("Relay dropped invalid outbound nats subject", "subject", msg.Subject)
		return
	}

	route, err := parseConcreteOutboundNATSSubject(msg.Subject)
	if err != nil {
		logger.Warn("Relay dropped invalid outbound route", "subject", msg.Subject)
		return
	}

	if _, ok := r.sessions.Get(route.CosignerID); !ok {
		logger.Info("Relay dropped outbound message for offline cosigner", "cosigner_id", route.CosignerID, "subject", msg.Subject)
		return
	}

	if err := r.mqttServer.Publish(topic, msg.Data, false, 0); err != nil {
		logger.Error("Failed to publish outbound nats message to mqtt", err, "subject", msg.Subject, "topic", topic)
		return
	}

	logger.Debug("Relayed nats message to mqtt", "subject", msg.Subject, "topic", topic)
}

func connectNATS(environment string, cfg *config.NATsConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.ReconnectBufSize(16 * 1024 * 1024),
		nats.Dialer(&net.Dialer{
			Timeout: 30 * time.Second,
		}),
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			logger.Warn("Relay disconnected from NATS", "error", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("Relay reconnected to NATS", "connected_url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			logger.Warn("Relay closed NATS connection")
		}),
	}

	if cfg.Username != "" || cfg.Password != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}

	if cfg.TLS != nil && cfg.TLS.ClientCert != "" && cfg.TLS.ClientKey != "" && cfg.TLS.CACert != "" {
		opts = append(opts,
			nats.ClientCert(cfg.TLS.ClientCert, cfg.TLS.ClientKey),
			nats.RootCAs(cfg.TLS.CACert),
		)
	}

	url := cfg.URL
	if environment != "production" && url == "" {
		url = "nats://127.0.0.1:4222"
	}

	return nats.Connect(url, opts...)
}

func mqttListenerID(cfg *config.RelayConfig) string {
	if cfg.MQTT.ListenerID == "" {
		return defaultMQTTListenerID
	}

	return cfg.MQTT.ListenerID
}

func mqttSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func validateRuntimeConfig(cfg *config.RelayConfig) error {
	if cfg == nil {
		return fmt.Errorf("relay config is required")
	}

	if cfg.NATs == nil || cfg.NATs.URL == "" {
		return fmt.Errorf("nats.url is required")
	}

	if cfg.MQTT == nil || cfg.MQTT.Address == "" {
		return fmt.Errorf("mqtt.address is required")
	}

	if cfg.Redis == nil || cfg.Redis.Addr == "" {
		return fmt.Errorf("redis.addr is required")
	}

	if cfg.Auth == nil || len(cfg.Auth.Cosigners) == 0 {
		return fmt.Errorf("auth.cosigners must contain at least one cosigner")
	}

	return nil
}
