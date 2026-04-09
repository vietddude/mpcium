package sdkflow

import "fmt"

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
	RootDir string `mapstructure:"root_dir"`
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
	if c.Runtime.IdentityStoreDir == "" {
		return fmt.Errorf("runtime.identity_store_dir is required")
	}
	if c.Storage.RootDir == "" {
		return fmt.Errorf("storage.root_dir is required")
	}
	return nil
}
