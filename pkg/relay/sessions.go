package relay

import (
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
)

type Session struct {
	CosignerID  string
	ClientID    string
	ConnectedAt time.Time
	Client      *mqtt.Client
}

type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		sessions: make(map[string]*Session),
	}
}

func (r *SessionRegistry) Register(session *Session) (previous *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	previous = r.sessions[session.CosignerID]
	r.sessions[session.CosignerID] = session
	return previous
}

func (r *SessionRegistry) Get(cosignerID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, ok := r.sessions[cosignerID]
	return session, ok
}

func (r *SessionRegistry) IsCurrent(cosignerID string, client *mqtt.Client) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, ok := r.sessions[cosignerID]
	return ok && session.Client == client
}

func (r *SessionRegistry) RemoveIfCurrent(cosignerID string, client *mqtt.Client) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.sessions[cosignerID]
	if !ok || session.Client != client {
		return false
	}

	delete(r.sessions, cosignerID)
	return true
}
