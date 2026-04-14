package runtime

import (
	"fmt"

	"github.com/fystack/mpcium/pkg/config"
)

func validateConfig(cfg *config.RelayConfig) error {
	if cfg == nil {
		return fmt.Errorf("relay config is required")
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
