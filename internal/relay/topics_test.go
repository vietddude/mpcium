package relay

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopicMapperRoundTrip(t *testing.T) {
	mapper := NewTopicMapper()

	subject := OutboundNATSSubject("cosigner-1", "wallet-1", "keygen", "round-1")

	topic, err := mapper.NatsToMQTT(subject)
	require.NoError(t, err)
	assert.Equal(t, MQTTTopic("cosigner-1", "wallet-1", "keygen", "round-1"), topic)

	inbound, err := mapper.MQTTToNATS(topic, "cosigner-1")
	require.NoError(t, err)
	assert.Equal(t, InboundNATSSubject("cosigner-1", "wallet-1", "keygen", "round-1"), inbound)
}

func TestTopicMapperRejectsInvalidShapes(t *testing.T) {
	mapper := NewTopicMapper()

	_, err := mapper.NatsToMQTT("mpc.relay.to_cosigner.cosigner-1.wallet-1")
	require.Error(t, err)

	_, err = mapper.MQTTToNATS("cosigner/cosigner-1/wallet-1", "cosigner-1")
	require.Error(t, err)

	_, err = mapper.NatsToMQTT("mpc.relay.to_cosigner.cosigner-1.wallet-1.>")
	require.Error(t, err)

	_, err = mapper.MQTTToNATS("cosigner/cosigner-1/wallet-1/+", "cosigner-1")
	require.Error(t, err)
}

func TestTopicMapperAllowsTargetMailboxDifferentFromAuthenticatedCosigner(t *testing.T) {
	mapper := NewTopicMapper()

	inbound, err := mapper.MQTTToNATS(MQTTTopic("cosigner-2", "wallet-1", "keygen"), "cosigner-1")
	require.NoError(t, err)
	assert.Equal(t, InboundNATSSubject("cosigner-2", "wallet-1", "keygen"), inbound)
}
