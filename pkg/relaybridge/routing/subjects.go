package routing

import (
	"fmt"
	"strings"

	relayprotocol "github.com/fystack/mpcium/internal/relay/protocol"
	rbtypes "github.com/fystack/mpcium/pkg/relaybridge/types"
)

const (
	// Request streams keep one stream per operation.
	KeygenRequestStream  = "mpc-sdk-keygen"
	SignRequestStream    = "mpc-sdk-sign"
	KeygenConsumerStream = "mpc-sdk-keygen-consumer"
	SignConsumerStream   = "mpc-sdk-sign-consumer"

	// Direct internal request subjects:
	//   mpc.sdk.req.<wallet_id>.<protocol>.<operation>.<session_id>
	requestSubjectPrefix = "mpc.sdk.req"

	// Direct internal session subjects:
	//   mpc.sdk.session.<participant_id>.<wallet_id>.<protocol>.<operation>.<session_id>.relaybridge
	sessionSubjectPrefix = "mpc.sdk.session"

	// Result subjects sent back to the client that created the request:
	//   mpc.sdk.keygen.res.<client_id>.<session_id>
	//   mpc.sdk.sign.res.<client_id>.<session_id>
	keygenResultSubjectPrefix = "mpc.sdk.keygen.res"
	signResultSubjectPrefix   = "mpc.sdk.sign.res"

	ResultStreamName  = "mpc_sdk_results"
	resultSubjectGlob = "mpc.sdk.>"

	// Relay request subjects are carried through the generic relay namespace as:
	//   mpc.relay.to_cosigner.<participant_id>.<wallet_id>.req.<protocol>.<operation>.<session_id>
	relayRequestTailPrefix = "req"

	// Relay session traffic uses the relay tail:
	//   ...<protocol>.<operation>.<session_id>.relaybridge
	relaySessionTail = "relaybridge"
)

// RequestTarget is the normalized routing info extracted back from a request subject.
// After parsing we know wallet/session/protocol/operation.
type RequestTarget struct {
	WalletID  string
	Protocol  rbtypes.Protocol
	Operation rbtypes.Operation
	SessionID string
}

// KeygenRequestSubject builds the direct NATS keygen subject:
// mpc.sdk.req.<wallet_id>.<protocol>.keygen.<session_id>
func KeygenRequestSubject(walletID string, protocol rbtypes.Protocol, sessionID string) string {
	return directRequestSubject(walletID, protocol, rbtypes.OperationKeygen, sessionID)
}

// KeygenRequestFilterSubject is what each runtime subscribes to for keygen requests.
func KeygenRequestFilterSubject() string {
	return directRequestFilterSubject(rbtypes.OperationKeygen)
}

// KeygenRequestTopic is the stream-wide wildcard subject for all keygen requests.
func KeygenRequestTopic() string {
	return directRequestTopic(rbtypes.OperationKeygen)
}

// SignRequestSubject builds the direct NATS sign subject:
// mpc.sdk.req.<wallet_id>.<protocol>.sign.<session_id>
func SignRequestSubject(walletID string, protocol rbtypes.Protocol, sessionID string) string {
	return directRequestSubject(walletID, protocol, rbtypes.OperationSign, sessionID)
}

// SignRequestFilterSubject is the wildcard for sign requests.
func SignRequestFilterSubject() string {
	return directRequestFilterSubject(rbtypes.OperationSign)
}

// SignRequestTopic is the stream-wide wildcard subject for all sign requests.
func SignRequestTopic() string {
	return directRequestTopic(rbtypes.OperationSign)
}

// KeygenResultSubject sends the final keygen result to the originating client:
// mpc.sdk.keygen.res.<client_id>.<session_id>
func KeygenResultSubject(clientID, sessionID string) string {
	return scopedSubject(keygenResultSubjectPrefix, clientID, sessionID)
}

// KeygenResultSubscriptionSubject subscribes to every keygen result for one client:
// mpc.sdk.keygen.res.<client_id>.*
func KeygenResultSubscriptionSubject(clientID string) string {
	return scopedSubject(keygenResultSubjectPrefix, clientID, "*")
}

// SignResultSubject sends the final sign result to the originating client:
// mpc.sdk.sign.res.<client_id>.<session_id>
func SignResultSubject(clientID, sessionID string) string {
	return scopedSubject(signResultSubjectPrefix, clientID, sessionID)
}

// SignResultSubscriptionSubject subscribes to every sign result for one client:
// mpc.sdk.sign.res.<client_id>.*
func SignResultSubscriptionSubject(clientID string) string {
	return scopedSubject(signResultSubjectPrefix, clientID, "*")
}

// ClientResultSubscriptionSubject is the broad wildcard when a client wants both result
// kinds with one pattern:
// mpc.sdk.*.res.<client_id>.*
func ClientResultSubscriptionSubject(clientID string) string {
	if clientID == "" {
		return resultSubjectGlob
	}
	return strings.Join([]string{"mpc", "sdk", "*", "res", clientID, "*"}, ".")
}

// ResultStreamSubjects are the stream capture patterns for all client-facing results.
func ResultStreamSubjects() []string {
	return []string{
		keygenResultSubjectPrefix + ".>",
		signResultSubjectPrefix + ".>",
	}
}

// DirectSessionSubject is used only between internal nodes over NATS:
// mpc.sdk.session.<participant_id>.<wallet_id>.<protocol>.<operation>.<session_id>.relaybridge
func DirectSessionSubject(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string) string {
	return strings.Join([]string{
		sessionSubjectPrefix,
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(protocol),
		string(operation),
		strings.TrimSpace(sessionID),
		relaySessionTail,
	}, ".")
}

// RelayInboundSessionSubject is what an internal runtime subscribes to for session traffic
// coming back from the relay/cosigner side:
// mpc.relay.from_cosigner.<participant_id>.<wallet_id>.<protocol>.<operation>.<session_id>.relaybridge
func RelayInboundSessionSubject(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string) string {
	return relayprotocol.InboundNATSSubject(
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(protocol),
		string(operation),
		strings.TrimSpace(sessionID),
		relaySessionTail,
	)
}

// RelayOutboundSessionSubject is where an internal runtime publishes session traffic
// destined for an external cosigner through the relay:
// mpc.relay.to_cosigner.<participant_id>.<wallet_id>.<protocol>.<operation>.<session_id>.relaybridge
func RelayOutboundSessionSubject(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string) string {
	return relayprotocol.OutboundNATSSubject(
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(protocol),
		string(operation),
		strings.TrimSpace(sessionID),
		relaySessionTail,
	)
}

// KeygenRelayRequestSubject sends an initial keygen request to a relay-backed participant:
// mpc.relay.to_cosigner.<participant_id>.<wallet_id>.req.<protocol>.keygen.<session_id>
func KeygenRelayRequestSubject(participantID, walletID string, protocol rbtypes.Protocol, sessionID string) string {
	return relayRequestSubject(participantID, walletID, protocol, rbtypes.OperationKeygen, sessionID)
}

// SignRelayRequestSubject sends an initial sign request to a relay-backed participant:
// mpc.relay.to_cosigner.<participant_id>.<wallet_id>.req.<protocol>.sign.<session_id>
func SignRelayRequestSubject(participantID, walletID string, protocol rbtypes.Protocol, sessionID string) string {
	return relayRequestSubject(participantID, walletID, protocol, rbtypes.OperationSign, sessionID)
}

// ParseDirectRequestSubject reverses:
// mpc.sdk.req.<wallet_id>.<protocol>.<operation>.<session_id>
func ParseDirectRequestSubject(subject string) (RequestTarget, error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 7 || strings.Join(parts[:3], ".") != requestSubjectPrefix {
		return RequestTarget{}, fmt.Errorf("invalid relaybridge direct request subject %q", subject)
	}
	return buildRequestTarget(parts[3], parts[4], parts[5], parts[6], subject)
}

// ParseRelayRequestSubject reverses:
// mpc.relay.from_cosigner.<participant_id>.<wallet_id>.req.<protocol>.<operation>.<session_id>
func ParseRelayRequestSubject(subject string) (RequestTarget, error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 9 || strings.Join(parts[:3], ".") != relayprotocol.InboundNATSSubjectPrefix {
		return RequestTarget{}, fmt.Errorf("invalid relaybridge relay request subject %q", subject)
	}
	if parts[5] != relayRequestTailPrefix {
		return RequestTarget{}, fmt.Errorf("invalid relaybridge relay request subject %q", subject)
	}
	if strings.TrimSpace(parts[3]) == "" {
		return RequestTarget{}, fmt.Errorf("invalid relaybridge relay request subject %q", subject)
	}
	return buildRequestTarget(parts[4], parts[6], parts[7], parts[8], subject)
}

func scopedSubject(prefix, clientID, tail string) string {
	parts := []string{prefix}
	if clientID != "" {
		parts = append(parts, clientID)
	}
	parts = append(parts, tail)
	return strings.Join(parts, ".")
}

func directRequestSubject(walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string) string {
	return strings.Join([]string{
		requestSubjectPrefix,
		strings.TrimSpace(walletID),
		string(protocol),
		string(operation),
		strings.TrimSpace(sessionID),
	}, ".")
}

func directRequestFilterSubject(operation rbtypes.Operation) string {
	return strings.Join([]string{
		requestSubjectPrefix,
		"*",
		"*",
		string(operation),
		"*",
	}, ".")
}

func directRequestTopic(operation rbtypes.Operation) string {
	return strings.Join([]string{
		requestSubjectPrefix,
		"*",
		"*",
		string(operation),
		"*",
	}, ".")
}

func relayRequestSubject(participantID, walletID string, protocol rbtypes.Protocol, operation rbtypes.Operation, sessionID string) string {
	return relayprotocol.OutboundNATSSubject(
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		relayRequestTailPrefix,
		string(protocol),
		string(operation),
		strings.TrimSpace(sessionID),
	)
}

func buildRequestTarget(walletID, protocolValue, operationValue, sessionID, subject string) (RequestTarget, error) {
	protocol := rbtypes.Protocol(strings.TrimSpace(protocolValue))
	switch protocol {
	case rbtypes.ProtocolECDSA, rbtypes.ProtocolEdDSA:
	default:
		return RequestTarget{}, fmt.Errorf("unsupported relaybridge request protocol %q", protocolValue)
	}
	operation := rbtypes.Operation(strings.TrimSpace(operationValue))
	switch operation {
	case rbtypes.OperationKeygen, rbtypes.OperationSign:
	default:
		return RequestTarget{}, fmt.Errorf("unsupported relaybridge request operation %q", operationValue)
	}

	target := RequestTarget{
		WalletID:  strings.TrimSpace(walletID),
		Protocol:  protocol,
		Operation: operation,
		SessionID: strings.TrimSpace(sessionID),
	}
	if target.WalletID == "" || target.SessionID == "" {
		return RequestTarget{}, fmt.Errorf("invalid relaybridge request subject %q", subject)
	}
	return target, nil
}
