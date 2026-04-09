package sdkflow

import "strings"

const (
	KeygenRequestStream  = "mpc-sdkflow-keygen"
	SignRequestStream    = "mpc-sdkflow-sign"
	KeygenConsumerStream = "mpc-sdkflow-keygen-consumer"
	SignConsumerStream   = "mpc-sdkflow-sign-consumer"

	keygenRequestSubjectPrefix = "mpc.sdkflow.keygen_request"
	signRequestSubjectPrefix   = "mpc.sdkflow.sign_request"

	keygenResultSubjectPrefix = "mpc.sdkflow.keygen_result"
	signResultSubjectPrefix   = "mpc.sdkflow.sign_result"
)

func KeygenRequestSubject(participantID string) string {
	return strings.Join([]string{keygenRequestSubjectPrefix, participantID}, ".")
}

func KeygenRequestTopic() string {
	return keygenRequestSubjectPrefix + ".*"
}

func SignRequestSubject(participantID string) string {
	return strings.Join([]string{signRequestSubjectPrefix, participantID}, ".")
}

func SignRequestTopic() string {
	return signRequestSubjectPrefix + ".*"
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

func ResultStreamSubjects() []string {
	return []string{
		keygenResultSubjectPrefix + ".>",
		signResultSubjectPrefix + ".>",
	}
}

func scopedSubject(prefix, clientID, tail string) string {
	parts := []string{prefix}
	if clientID != "" {
		parts = append(parts, clientID)
	}
	parts = append(parts, tail)
	return strings.Join(parts, ".")
}
