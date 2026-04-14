package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	rbclient "github.com/fystack/mpcium/internal/relaybridge/client"
	rbtypes "github.com/fystack/mpcium/internal/relaybridge/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type ExampleConfig struct {
	NATSURL  string                 `json:"nats_url"`
	ClientID string                 `json:"client_id"`
	Timeout  string                 `json:"timeout"`
	Keygen   *rbtypes.KeygenRequest `json:"keygen,omitempty"`
	Sign     *rbtypes.SignRequest   `json:"sign,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "Path to relaybridge example config JSON file")
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

	client := rbclient.New(rbclient.Options{
		NATSConn: nc,
		ClientID: cfg.ClientID,
	})
	defer client.Close()

	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		exitf("invalid timeout: %v", err)
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
		cfg.ClientID = "relaybridge-example"
	}
	if strings.TrimSpace(cfg.Timeout) == "" {
		cfg.Timeout = "60s"
	}
	if cfg.Keygen != nil {
		prepareSession(&cfg.Keygen.Session, rbtypes.OperationKeygen)
	}
	if cfg.Sign != nil {
		prepareSession(&cfg.Sign.Session, rbtypes.OperationSign)
	}

	return &cfg, nil
}

func prepareSession(session *rbtypes.SessionContext, operation rbtypes.Operation) {
	session.Operation = operation
	if strings.TrimSpace(session.SessionID) == "" {
		session.SessionID = uuid.NewString()
	}
	if strings.TrimSpace(session.WalletID) == "" {
		session.WalletID = uuid.NewString()
	}
}

func runKeygen(client rbclient.Client, req *rbtypes.KeygenRequest, timeout time.Duration) {
	startedAt := time.Now()
	expected := len(requestedKeygenProtocols(req.Session.Protocol))
	wait := make(chan rbtypes.KeygenResult, expected)
	if err := client.OnKeygenResult(func(result rbtypes.KeygenResult) {
		wait <- result
	}); err != nil {
		exitf("subscribe keygen result: %v", err)
	}

	if err := client.CreateKeygen(*req); err != nil {
		exitf("create keygen: %v", err)
	}

	results := make([]rbtypes.KeygenResult, 0, expected)
	deadline := time.After(timeout)
	for len(results) < expected {
		select {
		case result := <-wait:
			results = append(results, result)
		case <-deadline:
			exitf("timed out waiting for keygen result")
		}
	}

	if expected == 1 {
		printJSON(results[0])
		printSummary("keygen", startedAt, 1)
		return
	}
	printJSON(results)
	printSummary("keygen", startedAt, expected)
}

func runSign(client rbclient.Client, req *rbtypes.SignRequest, timeout time.Duration) {
	startedAt := time.Now()
	wait := make(chan rbtypes.SignResult, 1)
	if err := client.OnSignResult(func(result rbtypes.SignResult) {
		wait <- result
	}); err != nil {
		exitf("subscribe sign result: %v", err)
	}

	if err := client.Sign(*req); err != nil {
		exitf("sign: %v", err)
	}

	select {
	case result := <-wait:
		printJSON(result)
		printSummary("sign", startedAt, 1)
	case <-time.After(timeout):
		exitf("timed out waiting for sign result")
	}
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

func printSummary(operation string, startedAt time.Time, results int) {
	fmt.Printf(
		"completed operation=%s results=%d elapsed=%s\n",
		operation,
		results,
		time.Since(startedAt).Round(time.Millisecond),
	)
}

func requestedKeygenProtocols(protocol rbtypes.Protocol) []rbtypes.Protocol {
	switch normalized := rbtypes.Protocol(strings.ToLower(strings.TrimSpace(string(protocol)))); normalized {
	case "":
		return []rbtypes.Protocol{rbtypes.ProtocolECDSA, rbtypes.ProtocolEdDSA}
	default:
		return []rbtypes.Protocol{normalized}
	}
}
