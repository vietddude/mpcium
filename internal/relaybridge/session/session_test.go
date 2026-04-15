package session

import (
	"context"
	"testing"
	"time"

	"github.com/fystack/mpcium-sdk/mpcore"
	"github.com/fystack/mpcium-sdk/secure"
	st "github.com/fystack/mpcium/internal/relaybridge/sessiontransport"
	routing "github.com/fystack/mpcium/pkg/relaybridge/routing"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunKeyExchangePhaseRejectsNonKeyExchangeMessage(t *testing.T) {
	session := &stubSecureSession{status: secure.Status{WaitingForKeys: []string{"node1"}}}
	runner := newTestRunner(session)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msgCh := make(chan st.Delivery, 1)
	msgCh <- st.Delivery{Payload: testEncryptedDirectEnvelope()}

	err := runner.runKeyExchangePhase(ctx, msgCh, []secure.Message{testKeyExchangeSecureMessage("node0")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key exchange phase")
}

func TestRunKeyExchangePhaseTimesOutWithoutPeerKeyExchange(t *testing.T) {
	session := &stubSecureSession{status: secure.Status{WaitingForKeys: []string{"node1"}}}
	runner := newTestRunner(session)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := runner.runKeyExchangePhase(ctx, make(chan st.Delivery), []secure.Message{testKeyExchangeSecureMessage("node0")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout waiting for key exchange readiness")
}

func TestPublishOutboundRoutesRelaySubject(t *testing.T) {
	transport := &recordingSessionTransport{}
	runner := newTestRunner(&stubSecureSession{})
	runner.transport = transport

	err := runner.publishOutbound([]secure.Message{testKeyExchangeSecureMessage("node0")})
	require.NoError(t, err)
	require.Len(t, transport.published, 1)

	assert.Equal(t,
		routing.RelayOutboundSessionSubject("node1", "wallet-1", rbtypes.ProtocolECDSA, rbtypes.OperationKeygen, "session-1"),
		transport.published[0].subject,
	)
	assert.Equal(t, "node0", transport.published[0].envelope.SenderID)
	assert.Equal(t, []string{"node1"}, transport.published[0].envelope.RecipientIDs)
}

func TestHandleMPCEnvelopeRejectsKeyExchangeMessage(t *testing.T) {
	runner := newTestRunner(&stubSecureSession{})

	_, err := runner.handleMPCEnvelope(testKeyExchangeEnvelope())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "during mpc phase")
}

type recordingSessionTransport struct {
	published []publishedEnvelope
}

type publishedEnvelope struct {
	subject  string
	envelope st.Payload
}

func (r *recordingSessionTransport) Subscribe(_ []string) (st.Subscription, error) {
	return nil, nil
}

func (r *recordingSessionTransport) Publish(subject string, envelope st.Payload) error {
	r.published = append(r.published, publishedEnvelope{subject: subject, envelope: envelope})
	return nil
}

type stubSecureSession struct {
	status        secure.Status
	applied       []secure.Message
	applyErr      error
	startMPCErr   error
	startMPCRes   *mpcore.Result
	startMPCOut   []secure.Message
	startKeyExErr error
	startKeyExOut []secure.Message
}

func (s *stubSecureSession) StartKeyExchange() ([]secure.Message, error) {
	return append([]secure.Message(nil), s.startKeyExOut...), s.startKeyExErr
}

func (s *stubSecureSession) StartMPC() ([]secure.Message, *mpcore.Result, error) {
	return append([]secure.Message(nil), s.startMPCOut...), s.startMPCRes, s.startMPCErr
}

func (s *stubSecureSession) Apply(msg secure.Message) ([]secure.Message, *mpcore.Result, error) {
	s.applied = append(s.applied, msg)
	if s.applyErr != nil {
		return nil, nil, s.applyErr
	}
	if len(s.status.WaitingForKeys) > 0 {
		s.status.WaitingForKeys = nil
	}
	return nil, nil, nil
}

func (s *stubSecureSession) Status() secure.Status { return s.status }

func newTestRunner(session secureSession) *Runner {
	return &Runner{
		resolved: &ResolvedSession{
			Session: rbtypes.SessionContext{
				SessionID:          "session-1",
				WalletID:           "wallet-1",
				Protocol:           rbtypes.ProtocolECDSA,
				Operation:          rbtypes.OperationKeygen,
				LocalParticipantID: "node0",
				Participants: []rbtypes.Participant{
					{ID: "node0", ParticipantType: rbtypes.ParticipantNode},
					{ID: "node1", ParticipantType: rbtypes.ParticipantServer},
				},
			},
			Participants: []mpcore.Participant{{ID: "node0"}, {ID: "node1"}},
		},
		cfg: mpcore.SessionConfig{
			SessionID: "session-1",
			WalletID:  "wallet-1",
			Protocol:  mpcore.ProtocolECDSA,
			Operation: mpcore.OperationKeygen,
		},
		transport:            &recordingSessionTransport{},
		session:              session,
		keyExchangeSeenPeers: map[string]struct{}{},
	}
}

func testKeyExchangeSecureMessage(fromParticipantID string) secure.Message {
	return secure.Message{
		Type: secure.MessageTypeSignedBroadcast,
		SignedBroadcast: &secure.SignedBroadcastMessage{
			Kind: secure.BroadcastKindKeyExchange,
			KeyExchange: &secure.KeyExchangeMessage{
				SessionID:         "session-1",
				Protocol:          mpcore.ProtocolECDSA,
				Operation:         mpcore.OperationKeygen,
				Round:             "key_exchange",
				FromParticipantID: fromParticipantID,
				PublicKey:         []byte("pubkey"),
			},
			Signature: []byte("sig"),
		},
	}
}

func testKeyExchangeEnvelope() st.Payload {
	return st.Payload{
		SessionID: "session-1",
		WalletID:  "wallet-1",
		Protocol:  mpcore.ProtocolECDSA.String(),
		Operation: mpcore.OperationKeygen.String(),
		SenderID:  "node1",
		Message:   testKeyExchangeSecureMessage("node1"),
	}
}

func testEncryptedDirectEnvelope() st.Payload {
	return st.Payload{
		SessionID: "session-1",
		WalletID:  "wallet-1",
		Protocol:  mpcore.ProtocolECDSA.String(),
		Operation: mpcore.OperationKeygen.String(),
		SenderID:  "node1",
		Message: secure.Message{
			Type: secure.MessageTypeEncryptedDirect,
			EncryptedDirect: &secure.EncryptedDirectMessage{
				Message: secure.RoundMessage{
					SessionID:               "session-1",
					Protocol:                mpcore.ProtocolECDSA,
					Operation:               mpcore.OperationKeygen,
					Round:                   "round-1",
					FromParticipantID:       "node1",
					RecipientParticipantIDs: []string{"node0"},
					Broadcast:               false,
					Payload:                 []byte("payload"),
				},
				Nonce:      []byte("nonce"),
				Ciphertext: []byte("ciphertext"),
			},
		},
	}
}

var _ secureSession = (*stubSecureSession)(nil)
var _ st.Transport = (*recordingSessionTransport)(nil)
