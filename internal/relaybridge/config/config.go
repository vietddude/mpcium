package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Environment string         `mapstructure:"environment"`
	NATS        NATSConfig     `mapstructure:"nats"`
	Runtime     RuntimeConfig  `mapstructure:"runtime"`
	Storage     StorageConfig  `mapstructure:"storage"`
	Consumer    ConsumerConfig `mapstructure:"consumer"`
}

type NATSConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type RuntimeConfig struct {
	ParticipantID      string `mapstructure:"participant_id"`
	IdentityRef        string `mapstructure:"identity_ref"`
	IdentityStoreDir   string `mapstructure:"identity_store_dir"`
	PeerReadyTimeout   string `mapstructure:"peer_ready_timeout"`
	PeerReadyInterval  string `mapstructure:"peer_ready_interval"`
	ECDSAPreparamsPath string `mapstructure:"ecdsa_preparams_path"`
	RequestTimeout     string `mapstructure:"request_timeout"`
}

type StorageConfig struct {
	RootDir       string `mapstructure:"root_dir"`
	AgePassphrase string `mapstructure:"age_passphrase"`
}

type ConsumerConfig struct {
	MaxConcurrentKeygen int `mapstructure:"max_concurrent_keygen"`
	MaxConcurrentSign   int `mapstructure:"max_concurrent_sign"`
}

func (c Config) Validate() error {
	if c.NATS.URL == "" {
		return fmt.Errorf("nats.url is required")
	}
	if c.Runtime.ParticipantID == "" {
		return fmt.Errorf("runtime.participant_id is required")
	}
	if c.Storage.RootDir == "" {
		return fmt.Errorf("storage.root_dir is required")
	}
	if c.Storage.AgePassphrase == "" {
		return fmt.Errorf("storage.age_passphrase is required")
	}
	return nil
}

func (c Config) IdentityRef() string {
	if strings.TrimSpace(c.Runtime.IdentityRef) != "" {
		return c.Runtime.IdentityRef
	}
	return c.Runtime.ParticipantID
}

func (c Config) IdentityStorePath() string {
	if strings.TrimSpace(c.Runtime.IdentityStoreDir) != "" {
		return c.Runtime.IdentityStoreDir
	}
	return c.Storage.RootDir
}

func (c Config) KeyShareStorePath() string {
	return filepath.Join(c.Storage.RootDir, "keyshares-db")
}

func (c Config) ECDSAPreparamsPath() string {
	if strings.TrimSpace(c.Runtime.ECDSAPreparamsPath) != "" {
		return c.Runtime.ECDSAPreparamsPath
	}
	return filepath.Join(c.Storage.RootDir, "runtime", "ecdsa_preparams.json")
}

func (c Config) RequestTimeout() time.Duration {
	return parseDurationOrDefault(c.Runtime.RequestTimeout, 45*time.Second)
}

func (c Config) PeerReadyTimeout() time.Duration {
	return parseDurationOrDefault(c.Runtime.PeerReadyTimeout, 10*time.Second)
}

func (c Config) PeerReadyInterval() time.Duration {
	return parseDurationOrDefault(c.Runtime.PeerReadyInterval, 300*time.Millisecond)
}

func parseDurationOrDefault(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
