package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	relayauth "github.com/fystack/mpcium/internal/relay/auth"
	relaypresence "github.com/fystack/mpcium/internal/relay/presence"
	"github.com/fystack/mpcium/internal/relay/protocol"
	relaysession "github.com/fystack/mpcium/internal/relay/session"
	"github.com/fystack/mpcium/pkg/logger"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/nats-io/nats.go"
)

type relayHook struct {
	mqtt.HookBase

	server                *mqtt.Server
	credentials           relayauth.Store
	sessions              *relaysession.Registry
	presence              relaypresence.Store
	mapper                protocol.TopicMapper
	natsConn              *nats.Conn
	presenceEventsEnabled bool
	now                   func() time.Time

	mu            sync.RWMutex
	authenticated map[*mqtt.Client]*authenticatedClient
}

type authenticatedClient struct {
	CosignerID  string
	ClientID    string
	ConnectedAt time.Time
}

func newRelayHook(
	server *mqtt.Server,
	credentials relayauth.Store,
	sessions *relaysession.Registry,
	presence relaypresence.Store,
	mapper protocol.TopicMapper,
	natsConn *nats.Conn,
	presenceEventsEnabled bool,
) *relayHook {
	return &relayHook{
		server:                server,
		credentials:           credentials,
		sessions:              sessions,
		presence:              presence,
		mapper:                mapper,
		natsConn:              natsConn,
		presenceEventsEnabled: presenceEventsEnabled,
		now:                   time.Now,
		authenticated:         make(map[*mqtt.Client]*authenticatedClient),
	}
}

func (h *relayHook) ID() string {
	return "relay"
}

func (h *relayHook) Provides(b byte) bool {
	return b == mqtt.OnConnectAuthenticate ||
		b == mqtt.OnACLCheck ||
		b == mqtt.OnSessionEstablished ||
		b == mqtt.OnPacketProcessed ||
		b == mqtt.OnDisconnect ||
		b == mqtt.OnPublished ||
		b == mqtt.OnPublish
}

func (h *relayHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	cosignerID, err := h.credentials.Authenticate(context.Background(), string(pk.Connect.Username), string(pk.Connect.Password))
	if err != nil {
		logger.Warn("Relay auth failed", "client_id", cl.ID, "remote", cl.Net.Remote, "username", string(pk.Connect.Username))
		return false
	}

	h.setAuthenticated(cl, &authenticatedClient{
		CosignerID:  cosignerID,
		ClientID:    pk.Connect.ClientIdentifier,
		ConnectedAt: h.now().UTC(),
	})

	return true
}

func (h *relayHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	identity, ok := h.getAuthenticated(cl)
	if !ok {
		return false
	}

	return protocol.AllowedMQTTNamespace(topic, identity.CosignerID, write)
}

func (h *relayHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if pk.FixedHeader.Retain {
		return pk, packets.ErrRetainNotSupported
	}

	return pk, nil
}

func (h *relayHook) OnSessionEstablished(cl *mqtt.Client, _ packets.Packet) {
	identity, ok := h.getAuthenticated(cl)
	if !ok {
		return
	}

	previous := h.sessions.Register(&relaysession.Session{
		CosignerID:  identity.CosignerID,
		ClientID:    cl.ID,
		ConnectedAt: identity.ConnectedAt,
		Client:      cl,
	})

	ctx := context.Background()
	if err := h.presence.MarkOnline(ctx, identity.CosignerID, cl.ID, identity.ConnectedAt); err != nil {
		logger.Error("Failed to mark cosigner online", err, "cosigner_id", identity.CosignerID, "client_id", cl.ID)
	}

	if err := h.publishPresenceEvent(protocol.NewPresenceEvent(identity.CosignerID, protocol.PresenceStatusOnline, cl.ID, identity.ConnectedAt)); err != nil {
		logger.Error("Failed to publish online presence event", err, "cosigner_id", identity.CosignerID, "client_id", cl.ID)
	}

	logger.Info("Relay cosigner connected", "cosigner_id", identity.CosignerID, "client_id", cl.ID, "remote", cl.Net.Remote)

	if previous != nil && previous.Client != nil && previous.Client != cl {
		go func(prev *relaysession.Session) {
			if err := h.server.DisconnectClient(prev.Client, packets.ErrSessionTakenOver); err != nil && !errors.Is(err, mqtt.ErrConnectionClosed) {
				logger.Error("Failed to disconnect previous cosigner session", err, "cosigner_id", prev.CosignerID, "client_id", prev.ClientID)
			}
		}(previous)
	}
}

func (h *relayHook) OnPacketProcessed(cl *mqtt.Client, pk packets.Packet, err error) {
	if err != nil || cl.Net.Inline || pk.FixedHeader.Type == packets.Disconnect {
		return
	}

	identity, ok := h.getAuthenticated(cl)
	if !ok || !h.sessions.IsCurrent(identity.CosignerID, cl) {
		return
	}

	if touchErr := h.presence.Touch(context.Background(), identity.CosignerID, h.now().UTC()); touchErr != nil {
		logger.Error("Failed to update cosigner last_seen", touchErr, "cosigner_id", identity.CosignerID, "client_id", cl.ID)
	}
}

func (h *relayHook) OnPublished(cl *mqtt.Client, pk packets.Packet) {
	if cl.Net.Inline {
		return
	}

	identity, ok := h.getAuthenticated(cl)
	if !ok || !h.sessions.IsCurrent(identity.CosignerID, cl) {
		return
	}

	subject, err := h.mapper.MQTTToNATS(pk.TopicName, identity.CosignerID)
	if err != nil {
		logger.Warn("Relay dropped invalid inbound mqtt topic", "cosigner_id", identity.CosignerID, "client_id", cl.ID, "topic", pk.TopicName)
		return
	}

	msg := &nats.Msg{
		Subject: subject,
		Data:    pk.Payload,
		Header: nats.Header{
			protocol.HeaderRelayCosignerID: []string{identity.CosignerID},
			protocol.HeaderRelayClientID:   []string{cl.ID},
		},
	}

	if err := h.natsConn.PublishMsg(msg); err != nil {
		logger.Error("Failed to publish MQTT message to NATS", err, "cosigner_id", identity.CosignerID, "client_id", cl.ID, "subject", subject)
		return
	}

	if strings.HasSuffix(pk.TopicName, "/relaybridge") {
		logger.Debug(
			"Relay forwarded relaybridge message mqtt->nats",
			"cosigner_id", identity.CosignerID,
			"client_id", cl.ID,
			"topic", pk.TopicName,
			"subject", subject,
		)
	}
	logger.Debug("Relayed mqtt message to nats", "cosigner_id", identity.CosignerID, "client_id", cl.ID, "topic", pk.TopicName, "subject", subject)
}

func (h *relayHook) OnDisconnect(cl *mqtt.Client, err error, _ bool) {
	identity, ok := h.getAuthenticated(cl)
	if !ok {
		return
	}

	h.deleteAuthenticated(cl)
	if !h.sessions.RemoveIfCurrent(identity.CosignerID, cl) {
		return
	}

	at := h.now().UTC()
	if markErr := h.presence.MarkOffline(context.Background(), identity.CosignerID, at); markErr != nil {
		logger.Error("Failed to mark cosigner offline", markErr, "cosigner_id", identity.CosignerID, "client_id", cl.ID)
	}

	if eventErr := h.publishPresenceEvent(protocol.NewPresenceEvent(identity.CosignerID, protocol.PresenceStatusOffline, cl.ID, at)); eventErr != nil {
		logger.Error("Failed to publish offline presence event", eventErr, "cosigner_id", identity.CosignerID, "client_id", cl.ID)
	}

	logger.Info("Relay cosigner disconnected", "cosigner_id", identity.CosignerID, "client_id", cl.ID, "error", err)
}

func (h *relayHook) publishPresenceEvent(event protocol.PresenceEvent) error {
	if !h.presenceEventsEnabled {
		return nil
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return h.natsConn.Publish(protocol.PresenceEventSubject(event.CosignerID), payload)
}

func (h *relayHook) setAuthenticated(cl *mqtt.Client, identity *authenticatedClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authenticated[cl] = identity
}

func (h *relayHook) getAuthenticated(cl *mqtt.Client) (*authenticatedClient, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	identity, ok := h.authenticated[cl]
	return identity, ok
}

func (h *relayHook) deleteAuthenticated(cl *mqtt.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.authenticated, cl)
}
