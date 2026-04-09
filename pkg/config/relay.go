package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type RelayConfig struct {
	NATs                  *NATsConfig       `mapstructure:"nats"`
	MQTT                  *RelayMQTTConfig  `mapstructure:"mqtt"`
	Redis                 *RelayRedisConfig `mapstructure:"redis"`
	Auth                  *RelayAuthConfig  `mapstructure:"auth"`
	Environment           string            `mapstructure:"environment"`
	PresenceEventsEnabled bool              `mapstructure:"presence_events_enabled"`
}

type RelayMQTTConfig struct {
	Address    string `mapstructure:"address"`
	ListenerID string `mapstructure:"listener_id"`
}

type RelayRedisConfig struct {
	Addr      string        `mapstructure:"addr"`
	Password  string        `mapstructure:"password"`
	DB        int           `mapstructure:"db"`
	OnlineTTL time.Duration `mapstructure:"online_ttl"`
	KeyPrefix string        `mapstructure:"key_prefix"`
}

type RelayAuthConfig struct {
	Cosigners []RelayCosignerCredential `mapstructure:"cosigners"`
}

type RelayCosignerCredential struct {
	CosignerID string `mapstructure:"cosigner_id"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
}

func (c RelayConfig) MarshalJSONMask() string {
	clone := c

	if clone.NATs != nil {
		clone.NATs = &NATsConfig{
			URL:      clone.NATs.URL,
			Username: clone.NATs.Username,
			Password: strings.Repeat("*", len(clone.NATs.Password)),
			TLS:      clone.NATs.TLS,
		}
	}

	if clone.Redis != nil {
		clone.Redis = &RelayRedisConfig{
			Addr:      clone.Redis.Addr,
			Password:  strings.Repeat("*", len(clone.Redis.Password)),
			DB:        clone.Redis.DB,
			OnlineTTL: clone.Redis.OnlineTTL,
			KeyPrefix: clone.Redis.KeyPrefix,
		}
	}

	if clone.Auth != nil {
		clone.Auth = &RelayAuthConfig{
			Cosigners: make([]RelayCosignerCredential, 0, len(clone.Auth.Cosigners)),
		}
		for _, cosigner := range clone.Auth.Cosigners {
			clone.Auth.Cosigners = append(clone.Auth.Cosigners, RelayCosignerCredential{
				CosignerID: cosigner.CosignerID,
				Username:   cosigner.Username,
				Password:   strings.Repeat("*", len(cosigner.Password)),
			})
		}
	}

	bytes, err := json.Marshal(clone)
	if err != nil {
		logger.Error("Failed to marshal relay config", err)
	}

	return string(bytes)
}

func LoadRelayConfig() *RelayConfig {
	var cfg RelayConfig
	decoderConfig := &mapstructure.DecoderConfig{
		Result:           &cfg,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		logger.Fatal("Failed to create relay config decoder", err)
	}

	if err := decoder.Decode(viper.AllSettings()); err != nil {
		logger.Fatal("Failed to decode relay config", err)
	}

	if err := validateRelayConfig(&cfg); err != nil {
		logger.Fatal("Relay config validation failed", err)
	}

	return &cfg
}

func validateRelayConfig(cfg *RelayConfig) error {
	if cfg == nil {
		return fmt.Errorf("relay config is required")
	}

	if err := validateEnvironment(cfg.Environment); err != nil {
		return err
	}

	if cfg.NATs == nil || cfg.NATs.URL == "" {
		return fmt.Errorf("nats.url is required")
	}

	if cfg.MQTT == nil || cfg.MQTT.Address == "" {
		return fmt.Errorf("mqtt.address is required")
	}

	if cfg.Redis == nil || cfg.Redis.Addr == "" {
		return fmt.Errorf("redis.addr is required")
	}

	if cfg.Auth == nil || len(cfg.Auth.Cosigners) == 0 {
		return fmt.Errorf("auth.cosigners must contain at least one cosigner")
	}

	return nil
}
