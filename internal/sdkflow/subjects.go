package sdkflow

import (
	"fmt"
	"strings"

	"github.com/fystack/mpcium/internal/relay"
)

const (
	KeygenRequestStream  = "mpc-sdk-keygen"
	SignRequestStream    = "mpc-sdk-sign"
	KeygenConsumerStream = "mpc-sdk-keygen-consumer"
	SignConsumerStream   = "mpc-sdk-sign-consumer"

	requestSubjectPrefix = "mpc.sdk.req"
	sessionSubjectPrefix = "mpc.sdk.session"

	keygenResultSubjectPrefix = "mpc.sdk.keygen.res"
	signResultSubjectPrefix   = "mpc.sdk.sign.res"

	resultStreamName  = "mpc_sdk_results"
	resultSubjectGlob = "mpc.sdk.>"

	relayRequestTailPrefix = "req"
	relaySessionTail       = "sdkflow"
)

type requestTarget struct {
	ParticipantID string
	WalletID      string
	Operation     Operation
	SessionID     string
}

func KeygenRequestSubject(participantID, walletID, sessionID string) string {
	return directRequestSubject(participantID, walletID, OperationKeygen, sessionID)
}

func KeygenRequestFilterSubject(participantID string) string {
	return directRequestFilterSubject(participantID, OperationKeygen)
}

func KeygenRequestTopic() string {
	return directRequestTopic(OperationKeygen)
}

func SignRequestSubject(participantID, walletID, sessionID string) string {
	return directRequestSubject(participantID, walletID, OperationSign, sessionID)
}

func SignRequestFilterSubject(participantID string) string {
	return directRequestFilterSubject(participantID, OperationSign)
}

func SignRequestTopic() string {
	return directRequestTopic(OperationSign)
}

func KeygenResultSubject(clientID, sessionID string) string {
	return scopedSubject(keygenResultSubjectPrefix, clientID, sessionID)
}

func KeygenResultSubscriptionSubject(clientID string) string {
	return scopedSubject(keygenResultSubjectPrefix, clientID, "*")
}

func SignResultSubject(clientID, sessionID string) string {
	return scopedSubject(signResultSubjectPrefix, clientID, sessionID)
}

func SignResultSubscriptionSubject(clientID string) string {
	return scopedSubject(signResultSubjectPrefix, clientID, "*")
}

func ClientResultSubscriptionSubject(clientID string) string {
	if clientID == "" {
		return resultSubjectGlob
	}
	return strings.Join([]string{"mpc", "sdk", "*", "res", clientID, "*"}, ".")
}

func ResultStreamSubjects() []string {
	return []string{
		keygenResultSubjectPrefix + ".>",
		signResultSubjectPrefix + ".>",
	}
}

func DirectSessionSubject(participantID, walletID string, operation Operation, sessionID string) string {
	return strings.Join([]string{
		sessionSubjectPrefix,
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(operation),
		strings.TrimSpace(sessionID),
		relaySessionTail,
	}, ".")
}

func RelayInboundSessionSubject(participantID, walletID string, operation Operation, sessionID string) string {
	return relay.InboundNATSSubject(
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(operation),
		strings.TrimSpace(sessionID),
		relaySessionTail,
	)
}

func RelayOutboundSessionSubject(participantID, walletID string, operation Operation, sessionID string) string {
	return relay.OutboundNATSSubject(
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(operation),
		strings.TrimSpace(sessionID),
		relaySessionTail,
	)
}

func KeygenRelayRequestSubject(participantID, walletID, sessionID string) string {
	return relayRequestSubject(participantID, walletID, OperationKeygen, sessionID)
}

func SignRelayRequestSubject(participantID, walletID, sessionID string) string {
	return relayRequestSubject(participantID, walletID, OperationSign, sessionID)
}

func ParseDirectRequestSubject(subject string) (requestTarget, error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 7 || strings.Join(parts[:3], ".") != requestSubjectPrefix {
		return requestTarget{}, fmt.Errorf("invalid sdkflow direct request subject %q", subject)
	}
	return buildRequestTarget(parts[3], parts[4], parts[5], parts[6], subject)
}

func ParseRelayRequestSubject(subject string) (requestTarget, error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 8 || strings.Join(parts[:3], ".") != relay.InboundNATSSubjectPrefix {
		return requestTarget{}, fmt.Errorf("invalid sdkflow relay request subject %q", subject)
	}
	if parts[5] != relayRequestTailPrefix {
		return requestTarget{}, fmt.Errorf("invalid sdkflow relay request subject %q", subject)
	}
	return buildRequestTarget(parts[3], parts[4], parts[6], parts[7], subject)
}

func scopedSubject(prefix, clientID, tail string) string {
	parts := []string{prefix}
	if clientID != "" {
		parts = append(parts, clientID)
	}
	parts = append(parts, tail)
	return strings.Join(parts, ".")
}

func directRequestSubject(participantID, walletID string, operation Operation, sessionID string) string {
	return strings.Join([]string{
		requestSubjectPrefix,
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		string(operation),
		strings.TrimSpace(sessionID),
	}, ".")
}

func directRequestFilterSubject(participantID string, operation Operation) string {
	return strings.Join([]string{
		requestSubjectPrefix,
		strings.TrimSpace(participantID),
		"*",
		string(operation),
		"*",
	}, ".")
}

func directRequestTopic(operation Operation) string {
	return strings.Join([]string{
		requestSubjectPrefix,
		"*",
		"*",
		string(operation),
		"*",
	}, ".")
}

func relayRequestSubject(participantID, walletID string, operation Operation, sessionID string) string {
	return relay.OutboundNATSSubject(
		strings.TrimSpace(participantID),
		strings.TrimSpace(walletID),
		relayRequestTailPrefix,
		string(operation),
		strings.TrimSpace(sessionID),
	)
}

func buildRequestTarget(participantID, walletID, operationValue, sessionID, subject string) (requestTarget, error) {
	operation := Operation(strings.TrimSpace(operationValue))
	switch operation {
	case OperationKeygen, OperationSign:
	default:
		return requestTarget{}, fmt.Errorf("unsupported sdkflow request operation %q", operationValue)
	}

	target := requestTarget{
		ParticipantID: strings.TrimSpace(participantID),
		WalletID:      strings.TrimSpace(walletID),
		Operation:     operation,
		SessionID:     strings.TrimSpace(sessionID),
	}
	if target.ParticipantID == "" || target.WalletID == "" || target.SessionID == "" {
		return requestTarget{}, fmt.Errorf("invalid sdkflow request subject %q", subject)
	}
	return target, nil
}
