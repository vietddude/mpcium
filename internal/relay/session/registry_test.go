package session

import (
	"testing"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryTakeover(t *testing.T) {
	registry := NewRegistry()
	client1 := &mqtt.Client{}
	client2 := &mqtt.Client{}

	first := &Session{
		CosignerID:  "cosigner-1",
		ClientID:    "client-1",
		ConnectedAt: time.Now(),
		Client:      client1,
	}

	previous := registry.Register(first)
	assert.Nil(t, previous)
	assert.True(t, registry.IsCurrent("cosigner-1", client1))

	second := &Session{
		CosignerID:  "cosigner-1",
		ClientID:    "client-2",
		ConnectedAt: time.Now().Add(time.Second),
		Client:      client2,
	}

	previous = registry.Register(second)
	require.NotNil(t, previous)
	assert.Equal(t, "client-1", previous.ClientID)
	assert.False(t, registry.IsCurrent("cosigner-1", client1))
	assert.True(t, registry.IsCurrent("cosigner-1", client2))

	assert.False(t, registry.RemoveIfCurrent("cosigner-1", client1))
	assert.True(t, registry.RemoveIfCurrent("cosigner-1", client2))
	_, ok := registry.Get("cosigner-1")
	assert.False(t, ok)
}
