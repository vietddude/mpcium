package runtime

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/fystack/mpcium/internal/relay/auth"
	"github.com/fystack/mpcium/internal/relay/presence"
	"github.com/fystack/mpcium/internal/relay/protocol"
	"github.com/fystack/mpcium/internal/relay/session"
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
	sessions    *session.Registry
	mqttHook    *relayHook
	mapper      protocol.TopicMapper
}

func New(cfg *config.RelayConfig) (*Runtime, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	credentials, err := auth.NewStaticStore(cfg.Auth.Cosigners)
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

	sessions := session.NewRegistry()
	mapper := protocol.NewTopicMapper()
	mqttHook := newRelayHook(
		mqttServer,
		credentials,
		sessions,
		presence.NewStore(redisClient, cfg.Redis.KeyPrefix, cfg.Redis.OnlineTTL),
		mapper,
		natsConn,
		cfg.PresenceEventsEnabled,
	)

	if err := mqttServer.AddHook(mqttHook, nil); err != nil {
		natsConn.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("failed to add mqtt relay hook: %w", err)
	}

	return &Runtime{
		cfg:         cfg,
		mqttServer:  mqttServer,
		mqttAddress: listener.Address(),
		natsConn:    natsConn,
		redisClient: redisClient,
		sessions:    sessions,
		mqttHook:    mqttHook,
		mapper:      mapper,
	}, nil
}

func (r *Runtime) Start() error {
	sub, err := r.natsConn.Subscribe(protocol.OutboundNATSSubjectPrefix+".>", r.handleOutboundNATSMessage)
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
