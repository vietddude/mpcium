package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/fystack/mpcium/pkg/config"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeBridgePresenceAndACL(t *testing.T) {
	runtime, natsConn, redisClient := newRelayTestRuntime(t)

	presenceSub, err := natsConn.SubscribeSync(PresenceEventSubject("cosigner-1"))
	require.NoError(t, err)

	messages := make(chan pahomqtt.Message, 1)
	client := connectMQTTClient(t, runtime.MQTTAddress(), "client-a", "user-1", "secret-1", nil)
	t.Cleanup(func() { disconnectMQTTClient(client) })

	requireMQTTSubscribe(t, client, MQTTTopic("cosigner-1", "wallet-1", "#"), 1, func(_ pahomqtt.Client, msg pahomqtt.Message) {
		messages <- msg
	})

	onlineEvent := nextPresenceEvent(t, presenceSub)
	assert.Equal(t, PresenceStatusOnline, onlineEvent.Status)
	assert.Equal(t, "cosigner-1", onlineEvent.CosignerID)
	assert.Equal(t, "client-a", onlineEvent.ClientID)

	require.Eventually(t, func() bool {
		values, err := redisClient.HGetAll(context.Background(), "cosigner:cosigner-1:presence").Result()
		if err != nil {
			return false
		}
		return values["online"] == "1" && values["client_id"] == "client-a"
	}, 5*time.Second, 50*time.Millisecond)

	outboundSubject := OutboundNATSSubject("cosigner-1", "wallet-1", "keygen", "round-1")
	require.NoError(t, natsConn.Publish(outboundSubject, []byte("outbound-payload")))

	select {
	case msg := <-messages:
		assert.Equal(t, MQTTTopic("cosigner-1", "wallet-1", "keygen", "round-1"), msg.Topic())
		assert.Equal(t, "outbound-payload", string(msg.Payload()))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for outbound mqtt message")
	}

	inboundSubject := InboundNATSSubject("cosigner-1", "wallet-1", "keygen", "round-2")
	inboundSub, err := natsConn.SubscribeSync(inboundSubject)
	require.NoError(t, err)

	requireMQTTPublish(t, client, MQTTTopic("cosigner-1", "wallet-1", "keygen", "round-2"), 1, false, []byte("inbound-payload"))

	natsMsg, err := inboundSub.NextMsg(5 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "inbound-payload", string(natsMsg.Data))
	assert.Equal(t, "cosigner-1", natsMsg.Header.Get(HeaderRelayCosignerID))
	assert.Equal(t, "client-a", natsMsg.Header.Get(HeaderRelayClientID))

	subscribeToken := client.Subscribe(MQTTTopic("cosigner-2", "wallet-1", "#"), 1, nil)
	require.True(t, subscribeToken.WaitTimeout(5*time.Second))
	require.NoError(t, subscribeToken.Error())
	assert.GreaterOrEqual(t, subscribeToken.(*pahomqtt.SubscribeToken).Result()[MQTTTopic("cosigner-2", "wallet-1", "#")], byte(0x80))

	forbiddenSub, err := natsConn.SubscribeSync(InboundNATSSubject("cosigner-2", "wallet-1", "keygen"))
	require.NoError(t, err)
	publishToken := client.Publish(MQTTTopic("cosigner-2", "wallet-1", "keygen"), 1, false, []byte("forbidden"))
	require.True(t, publishToken.WaitTimeout(5*time.Second))
	require.NoError(t, publishToken.Error())
	forwarded, err := forbiddenSub.NextMsg(5 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "forbidden", string(forwarded.Data))

	disconnectMQTTClient(client)
	offlineEvent := nextPresenceEvent(t, presenceSub)
	assert.Equal(t, PresenceStatusOffline, offlineEvent.Status)
	assert.Equal(t, "cosigner-1", offlineEvent.CosignerID)

	require.Eventually(t, func() bool {
		values, err := redisClient.HGetAll(context.Background(), "cosigner:cosigner-1:presence").Result()
		if err != nil {
			return false
		}
		return values["online"] == "0"
	}, 5*time.Second, 50*time.Millisecond)
}

func TestRuntimeRejectsInvalidAuthAndMarksAbruptDisconnectOffline(t *testing.T) {
	runtime, natsConn, redisClient := newRelayTestRuntime(t)

	badClient := newMQTTClient(runtime.MQTTAddress(), "bad-client", "user-1", "wrong", nil)
	badToken := badClient.Connect()
	require.True(t, badToken.WaitTimeout(5*time.Second))
	require.Error(t, badToken.Error())

	_, err := redisClient.HGetAll(context.Background(), "cosigner:cosigner-1:presence").Result()
	require.NoError(t, err)
	assert.False(t, redisClient.Exists(context.Background(), "cosigner:cosigner-1:presence").Val() > 0)

	presenceSub, err := natsConn.SubscribeSync(PresenceEventSubject("cosigner-1"))
	require.NoError(t, err)

	var rawConn net.Conn
	client := connectMQTTClient(t, runtime.MQTTAddress(), "client-b", "user-1", "secret-1", func(opts *pahomqtt.ClientOptions) {
		opts.SetKeepAlive(5 * time.Second)
		opts.SetCustomOpenConnectionFn(func(uri *url.URL, options pahomqtt.ClientOptions) (net.Conn, error) {
			conn, dialErr := net.Dial("tcp", uri.Host)
			if dialErr != nil {
				return nil, dialErr
			}
			rawConn = conn
			return conn, nil
		})
	})
	t.Cleanup(func() { disconnectMQTTClient(client) })

	_ = nextPresenceEvent(t, presenceSub)
	require.NotNil(t, rawConn)
	require.NoError(t, rawConn.Close())

	offlineEvent := nextPresenceEvent(t, presenceSub)
	assert.Equal(t, PresenceStatusOffline, offlineEvent.Status)
	assert.Equal(t, "cosigner-1", offlineEvent.CosignerID)

	require.Eventually(t, func() bool {
		values, err := redisClient.HGetAll(context.Background(), "cosigner:cosigner-1:presence").Result()
		if err != nil {
			return false
		}
		return values["online"] == "0"
	}, 5*time.Second, 50*time.Millisecond)
}

func newRelayTestRuntime(t *testing.T) (*Runtime, *nats.Conn, *redis.Client) {
	t.Helper()

	ns := startTestNATSServer(t)
	miniRedis := startMiniRedis(t)
	redisClient := redis.NewClient(&redis.Options{Addr: miniRedis.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	cfg := &config.RelayConfig{
		Environment:           "development",
		PresenceEventsEnabled: true,
		NATs: &config.NATsConfig{
			URL: ns.ClientURL(),
		},
		MQTT: &config.RelayMQTTConfig{
			Address:    "127.0.0.1:0",
			ListenerID: "relay-test",
		},
		Redis: &config.RelayRedisConfig{
			Addr:      miniRedis.Addr(),
			DB:        0,
			OnlineTTL: 30 * time.Second,
			KeyPrefix: "cosigner",
		},
		Auth: &config.RelayAuthConfig{
			Cosigners: []config.RelayCosignerCredential{
				{
					CosignerID: "cosigner-1",
					Username:   "user-1",
					Password:   "secret-1",
				},
			},
		},
	}

	runtime, err := NewRuntime(cfg)
	require.NoError(t, err)
	require.NoError(t, runtime.Start())
	t.Cleanup(func() { _ = runtime.Close() })

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	return runtime, nc, redisClient
}

func startTestNATSServer(t *testing.T) *natsserver.Server {
	t.Helper()

	server, err := natsserver.NewServer(&natsserver.Options{
		Host:   "127.0.0.1",
		Port:   -1,
		NoLog:  true,
		NoSigs: true,
	})
	require.NoError(t, err)

	go server.Start()
	require.True(t, server.ReadyForConnections(5*time.Second))
	t.Cleanup(server.Shutdown)

	return server
}

func startMiniRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()

	mini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mini.Close)
	return mini
}

func connectMQTTClient(
	t *testing.T,
	address, clientID, username, password string,
	customize func(opts *pahomqtt.ClientOptions),
) pahomqtt.Client {
	t.Helper()

	client := newMQTTClient(address, clientID, username, password, customize)
	token := client.Connect()
	require.True(t, token.WaitTimeout(5*time.Second))
	require.NoError(t, token.Error())
	return client
}

func newMQTTClient(
	address, clientID, username, password string,
	customize func(opts *pahomqtt.ClientOptions),
) pahomqtt.Client {
	opts := pahomqtt.NewClientOptions().
		AddBroker(fmt.Sprintf("tcp://%s", address)).
		SetClientID(clientID).
		SetUsername(username).
		SetPassword(password).
		SetAutoReconnect(false).
		SetConnectRetry(false).
		SetCleanSession(true)

	if customize != nil {
		customize(opts)
	}

	return pahomqtt.NewClient(opts)
}

func requireMQTTSubscribe(t *testing.T, client pahomqtt.Client, topic string, qos byte, handler pahomqtt.MessageHandler) {
	t.Helper()

	token := client.Subscribe(topic, qos, handler)
	require.True(t, token.WaitTimeout(5*time.Second))
	require.NoError(t, token.Error())
}

func requireMQTTPublish(t *testing.T, client pahomqtt.Client, topic string, qos byte, retained bool, payload []byte) {
	t.Helper()

	token := client.Publish(topic, qos, retained, payload)
	require.True(t, token.WaitTimeout(5*time.Second))
	require.NoError(t, token.Error())
}

func disconnectMQTTClient(client pahomqtt.Client) {
	if client != nil && client.IsConnected() {
		client.Disconnect(250)
	}
}

func nextPresenceEvent(t *testing.T, sub *nats.Subscription) PresenceEvent {
	t.Helper()

	msg, err := sub.NextMsg(5 * time.Second)
	require.NoError(t, err)

	var event PresenceEvent
	require.NoError(t, json.Unmarshal(msg.Data, &event))
	return event
}
