package runtime

import (
	"strings"

	"github.com/fystack/mpcium/internal/relay/protocol"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/nats-io/nats.go"
)

func (r *Runtime) handleOutboundNATSMessage(msg *nats.Msg) {
	topic, err := r.mapper.NatsToMQTT(msg.Subject)
	if err != nil {
		logger.Warn("Relay dropped invalid outbound nats subject", "subject", msg.Subject)
		return
	}

	cosignerID, _, _, err := protocol.ParseConcreteOutboundNATSSubject(msg.Subject)
	if err != nil {
		logger.Warn("Relay dropped invalid outbound route", "subject", msg.Subject)
		return
	}

	if _, ok := r.sessions.Get(cosignerID); !ok {
		logger.Info(
			"Relay dropped outbound message without active MQTT cosigner session",
			"cosigner_id", cosignerID,
			"subject", msg.Subject,
		)
		return
	}

	if err := r.mqttServer.Publish(topic, msg.Data, false, 0); err != nil {
		logger.Error("Failed to publish outbound nats message to mqtt", err, "subject", msg.Subject, "topic", topic)
		return
	}

	if strings.HasSuffix(msg.Subject, ".relaybridge") {
		logger.Debug(
			"Relay forwarded relaybridge message nats->mqtt",
			"cosigner_id", cosignerID,
			"subject", msg.Subject,
			"topic", topic,
		)
	}
	logger.Debug("Relayed nats message to mqtt", "subject", msg.Subject, "topic", topic)
}
