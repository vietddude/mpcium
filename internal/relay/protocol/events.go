package protocol

import "time"

const (
	PresenceStatusOnline  = "online"
	PresenceStatusOffline = "offline"
)

const (
	HeaderRelayCosignerID = "X-Relay-Cosigner-ID"
	HeaderRelayClientID   = "X-Relay-MQTT-Client-ID"
)

type PresenceEvent struct {
	CosignerID string `json:"cosigner_id"`
	Status     string `json:"status"`
	ClientID   string `json:"client_id,omitempty"`
	Timestamp  string `json:"timestamp"`
}

func NewPresenceEvent(cosignerID, status, clientID string, at time.Time) PresenceEvent {
	return PresenceEvent{
		CosignerID: cosignerID,
		Status:     status,
		ClientID:   clientID,
		Timestamp:  at.UTC().Format(time.RFC3339),
	}
}
