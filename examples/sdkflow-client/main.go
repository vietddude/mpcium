package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fystack/mpcium/internal/sdkflow"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type ExampleConfig struct {
	NATSURL  string                 `json:"nats_url"`
	ClientID string                 `json:"client_id"`
	Timeout  string                 `json:"timeout"`
	Keygen   *sdkflow.KeygenRequest `json:"keygen,omitempty"`
	Sign     *sdkflow.SignRequest   `json:"sign,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "Path to sdkflow example config JSON file")
	flag.Parse()

	if strings.TrimSpace(*configPath) == "" {
		exitf("config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		exitf("load config: %v", err)
	}

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		exitf("connect nats: %v", err)
	}
	defer nc.Close()

	client := sdkflow.NewClient(sdkflow.ClientOptions{
		NatsConn: nc,
		ClientID: cfg.ClientID,
	})
	defer client.Close()

	timeout := 60 * time.Second
	if cfg.Timeout != "" {
		parsed, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			exitf("invalid timeout: %v", err)
		}
		timeout = parsed
	}

	switch {
	case cfg.Keygen != nil:
		runKeygen(client, cfg.Keygen, timeout)
	case cfg.Sign != nil:
		runSign(client, cfg.Sign, timeout)
	default:
		exitf("config must contain either keygen or sign")
	}
}

func runKeygen(client sdkflow.Client, req *sdkflow.KeygenRequest, timeout time.Duration) {
	if strings.TrimSpace(req.Session.SessionID) == "" {
		req.Session.SessionID = uuid.NewString()
	}
	if strings.TrimSpace(req.Session.KeyID) == "" {
		req.Session.KeyID = req.Session.WalletID
	}
	req.Session.Operation = "keygen"

	wait := make(chan sdkflow.KeygenResult, 1)
	if err := client.OnKeygenResult(func(result sdkflow.KeygenResult) {
		if result.SessionID == req.Session.SessionID {
			wait <- result
		}
	}); err != nil {
		exitf("subscribe keygen result: %v", err)
	}

	if err := client.CreateKeygen(*req); err != nil {
		exitf("create keygen: %v", err)
	}

	fmt.Printf("sent keygen request session_id=%s wallet_id=%s\n", req.Session.SessionID, req.Session.WalletID)
	select {
	case result := <-wait:
		printJSON(result)
	case <-time.After(timeout):
		exitf("timed out waiting for keygen result")
	}
}

func runSign(client sdkflow.Client, req *sdkflow.SignRequest, timeout time.Duration) {
	if strings.TrimSpace(req.Session.SessionID) == "" {
		req.Session.SessionID = uuid.NewString()
	}
	if strings.TrimSpace(req.Session.KeyID) == "" {
		req.Session.KeyID = req.Session.WalletID
	}
	req.Session.Operation = "sign"

	wait := make(chan sdkflow.SignResult, 1)
	if err := client.OnSignResult(func(result sdkflow.SignResult) {
		if result.SessionID == req.Session.SessionID {
			wait <- result
		}
	}); err != nil {
		exitf("subscribe sign result: %v", err)
	}

	if err := client.Sign(*req); err != nil {
		exitf("sign: %v", err)
	}

	fmt.Printf("sent sign request session_id=%s wallet_id=%s signers=%v\n", req.Session.SessionID, req.Session.WalletID, req.SignerIndexes)
	select {
	case result := <-wait:
		printJSON(result)
	case <-time.After(timeout):
		exitf("timed out waiting for sign result")
	}
}

func loadConfig(path string) (*ExampleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ExampleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.NATSURL) == "" {
		cfg.NATSURL = "nats://127.0.0.1:4222"
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		cfg.ClientID = "sdkflow-example"
	}
	return &cfg, nil
}

func printJSON(value any) {
	blob, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		exitf("marshal result: %v", err)
	}
	fmt.Println(string(blob))
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
