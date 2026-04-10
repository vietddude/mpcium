package relay

import (
	"fmt"
	"strings"
)

const (
	OutboundNATSSubjectPrefix = "mpc.relay.to_cosigner"
	InboundNATSSubjectPrefix  = "mpc.relay.from_cosigner"
	PresenceSubjectPrefix     = "mpc.relay.cosigner.status"
	MQTTTopicPrefix           = "cosigner"
)

var (
	ErrInvalidNATSSubject     = fmt.Errorf("invalid relay nats subject")
	ErrInvalidMQTTTopic       = fmt.Errorf("invalid relay mqtt topic")
	ErrInvalidOutboundSubject = fmt.Errorf("invalid outbound relay nats subject")
)

type TopicMapper interface {
	NatsToMQTT(subject string) (string, error)
	MQTTToNATS(topic, authenticatedCosignerID string) (string, error)
}

type topicMapper struct{}

type transportRoute struct {
	CosignerID string
	WalletID   string
	Tail       []string
}

func NewTopicMapper() TopicMapper {
	return topicMapper{}
}

func (topicMapper) NatsToMQTT(subject string) (string, error) {
	route, err := parseConcreteOutboundNATSSubject(subject)
	if err != nil {
		return "", err
	}

	parts := []string{MQTTTopicPrefix, route.CosignerID, route.WalletID}
	parts = append(parts, route.Tail...)
	return strings.Join(parts, "/"), nil
}

func (topicMapper) MQTTToNATS(topic, _ string) (string, error) {
	route, err := parseConcreteMQTTTopic(topic)
	if err != nil {
		return "", err
	}

	parts := []string{InboundNATSSubjectPrefix, route.CosignerID, route.WalletID}
	parts = append(parts, route.Tail...)
	return strings.Join(parts, "."), nil
}

func OutboundNATSSubject(cosignerID, walletID string, tail ...string) string {
	return strings.Join(append([]string{OutboundNATSSubjectPrefix, cosignerID, walletID}, tail...), ".")
}

func InboundNATSSubject(cosignerID, walletID string, tail ...string) string {
	return strings.Join(append([]string{InboundNATSSubjectPrefix, cosignerID, walletID}, tail...), ".")
}

func MQTTTopic(cosignerID, walletID string, tail ...string) string {
	return strings.Join(append([]string{MQTTTopicPrefix, cosignerID, walletID}, tail...), "/")
}

func PresenceEventSubject(cosignerID string) string {
	return PresenceSubjectPrefix + "." + cosignerID
}

func parseConcreteOutboundNATSSubject(subject string) (transportRoute, error) {
	parts := strings.Split(subject, ".")
	if len(parts) < 6 || strings.Join(parts[:3], ".") != OutboundNATSSubjectPrefix {
		return transportRoute{}, ErrInvalidOutboundSubject
	}

	return buildNATSRoute(parts[3], parts[4], parts[5:])
}

func parseConcreteMQTTTopic(topic string) (transportRoute, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 4 || parts[0] != MQTTTopicPrefix {
		return transportRoute{}, ErrInvalidMQTTTopic
	}

	return buildMQTTRoute(parts[1], parts[2], parts[3:])
}

func buildNATSRoute(cosignerID, walletID string, tail []string) (transportRoute, error) {
	if err := validateSegments(cosignerID, walletID); err != nil {
		return transportRoute{}, err
	}
	if err := validateNATSTail(tail); err != nil {
		return transportRoute{}, err
	}

	return transportRoute{
		CosignerID: cosignerID,
		WalletID:   walletID,
		Tail:       append([]string(nil), tail...),
	}, nil
}

func buildMQTTRoute(cosignerID, walletID string, tail []string) (transportRoute, error) {
	if err := validateSegments(cosignerID, walletID); err != nil {
		return transportRoute{}, err
	}
	if err := validateMQTTTail(tail); err != nil {
		return transportRoute{}, err
	}

	return transportRoute{
		CosignerID: cosignerID,
		WalletID:   walletID,
		Tail:       append([]string(nil), tail...),
	}, nil
}

func validateSegments(segments ...string) error {
	for _, segment := range segments {
		if segment == "" {
			return ErrInvalidNATSSubject
		}
		if strings.ContainsAny(segment, "./+#*>") {
			return ErrInvalidNATSSubject
		}
	}
	return nil
}

func validateNATSTail(tail []string) error {
	if len(tail) == 0 {
		return ErrInvalidNATSSubject
	}

	for _, segment := range tail {
		if segment == "" || strings.ContainsAny(segment, "*>") {
			return ErrInvalidNATSSubject
		}
	}

	return nil
}

func validateMQTTTail(tail []string) error {
	if len(tail) == 0 {
		return ErrInvalidMQTTTopic
	}

	for _, segment := range tail {
		if segment == "" || strings.ContainsAny(segment, "+#") {
			return ErrInvalidMQTTTopic
		}
	}

	return nil
}

func allowedMQTTNamespace(topic, cosignerID string, write bool) bool {
	if write {
		return strings.HasPrefix(topic, MQTTTopicPrefix+"/") && !strings.ContainsAny(topic, "+#")
	}

	base := MQTTTopicPrefix + "/" + cosignerID
	if topic == base || strings.HasPrefix(topic, base+"/") {
		return true
	}

	return false
}
