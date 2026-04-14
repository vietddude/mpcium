package protocol

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
	route, err := parseOutboundNATSSubject(subject)
	if err != nil {
		return "", err
	}
	return strings.Join(append([]string{MQTTTopicPrefix, route.CosignerID, route.WalletID}, route.Tail...), "/"), nil
}

func (topicMapper) MQTTToNATS(topic, _ string) (string, error) {
	route, err := parseMQTTTopic(topic)
	if err != nil {
		return "", err
	}
	return strings.Join(append([]string{InboundNATSSubjectPrefix, route.CosignerID, route.WalletID}, route.Tail...), "."), nil
}

// Subject / topic builders

func OutboundNATSSubject(cosignerID, walletID string, tail ...string) string {
	return joinDot(OutboundNATSSubjectPrefix, cosignerID, walletID, tail)
}

func InboundNATSSubject(cosignerID, walletID string, tail ...string) string {
	return joinDot(InboundNATSSubjectPrefix, cosignerID, walletID, tail)
}

func MQTTTopic(cosignerID, walletID string, tail ...string) string {
	return joinSlash(MQTTTopicPrefix, cosignerID, walletID, tail)
}

func PresenceEventSubject(cosignerID string) string {
	return PresenceSubjectPrefix + "." + cosignerID
}

func AllowedMQTTNamespace(topic, cosignerID string, write bool) bool {
	if write {
		return strings.HasPrefix(topic, MQTTTopicPrefix+"/") && !strings.ContainsAny(topic, "+#")
	}
	base := MQTTTopicPrefix + "/" + cosignerID
	return topic == base || strings.HasPrefix(topic, base+"/")
}

// ParseConcreteOutboundNATSSubject parses a concrete outbound NATS subject into its components.
func ParseConcreteOutboundNATSSubject(subject string) (cosignerID, walletID string, tail []string, err error) {
	route, err := parseOutboundNATSSubject(subject)
	if err != nil {
		return "", "", nil, err
	}
	return route.CosignerID, route.WalletID, route.Tail, nil
}

// Parsers

func parseOutboundNATSSubject(subject string) (transportRoute, error) {
	parts := strings.Split(subject, ".")
	if len(parts) < 6 || strings.Join(parts[:3], ".") != OutboundNATSSubjectPrefix {
		return transportRoute{}, ErrInvalidOutboundSubject
	}
	return buildRoute(parts[3], parts[4], parts[5:], validateNATSTail, ErrInvalidNATSSubject)
}

func parseMQTTTopic(topic string) (transportRoute, error) {
	parts := strings.Split(topic, "/")
	if len(parts) < 4 || parts[0] != MQTTTopicPrefix {
		return transportRoute{}, ErrInvalidMQTTTopic
	}
	return buildRoute(parts[1], parts[2], parts[3:], validateMQTTTail, ErrInvalidMQTTTopic)
}

// buildRoute is the shared core for both NATS and MQTT route construction.
func buildRoute(cosignerID, walletID string, tail []string, validateTail func([]string) error, invalidErr error) (transportRoute, error) {
	if err := validateSegments(invalidErr, cosignerID, walletID); err != nil {
		return transportRoute{}, err
	}
	if err := validateTail(tail); err != nil {
		return transportRoute{}, err
	}
	return transportRoute{
		CosignerID: cosignerID,
		WalletID:   walletID,
		Tail:       append([]string(nil), tail...),
	}, nil
}

// Validators

func validateSegments(invalidErr error, segments ...string) error {
	for _, s := range segments {
		if s == "" || strings.ContainsAny(s, "./+#*>") {
			return invalidErr
		}
	}
	return nil
}

func validateNATSTail(tail []string) error {
	if len(tail) == 0 {
		return ErrInvalidNATSSubject
	}
	for _, s := range tail {
		if s == "" || strings.ContainsAny(s, "*>") {
			return ErrInvalidNATSSubject
		}
	}
	return nil
}

func validateMQTTTail(tail []string) error {
	if len(tail) == 0 {
		return ErrInvalidMQTTTopic
	}
	for _, s := range tail {
		if s == "" || strings.ContainsAny(s, "+#") {
			return ErrInvalidMQTTTopic
		}
	}
	return nil
}

// Helpers

func joinDot(prefix, cosignerID, walletID string, tail []string) string {
	return strings.Join(append([]string{prefix, cosignerID, walletID}, tail...), ".")
}

func joinSlash(prefix, cosignerID, walletID string, tail []string) string {
	return strings.Join(append([]string{prefix, cosignerID, walletID}, tail...), "/")
}
