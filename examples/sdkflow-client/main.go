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
	fmt.Printf("loaded config path=%s nats_url=%s client_id=%s timeout=%s\n", *configPath, cfg.NATSURL, cfg.ClientID, cfg.Timeout)

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		exitf("connect nats: %v", err)
	}
	defer nc.Close()
	fmt.Printf("connected to nats url=%s\n", cfg.NATSURL)

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
	req.Session.Operation = sdkflow.OperationKeygen
	logSession("keygen", req.Session)

	wait := make(chan sdkflow.KeygenResult, 1)
	if err := client.OnKeygenResult(func(result sdkflow.KeygenResult) {
		if result.SessionID == req.Session.SessionID {
			fmt.Printf("received keygen callback session_id=%s result_type=%s\n", result.SessionID, result.ResultType)
			wait <- result
		}
	}); err != nil {
		exitf("subscribe keygen result: %v", err)
	}
	fmt.Printf("subscribed keygen result session_id=%s client_id listener ready\n", req.Session.SessionID)

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
	req.Session.Operation = sdkflow.OperationSign
	logSession("sign", req.Session)
	fmt.Printf("signer_indexes=%v message_digest_len=%d\n", req.SignerIndexes, len(req.MessageDigestHex))

	wait := make(chan sdkflow.SignResult, 1)
	if err := client.OnSignResult(func(result sdkflow.SignResult) {
		if result.SessionID == req.Session.SessionID {
			fmt.Printf("received sign callback session_id=%s result_type=%s\n", result.SessionID, result.ResultType)
			wait <- result
		}
	}); err != nil {
		exitf("subscribe sign result: %v", err)
	}
	fmt.Printf("subscribed sign result session_id=%s client_id listener ready\n", req.Session.SessionID)

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

func logSession(kind string, session sdkflow.SessionContext) {
	fmt.Printf(
		"preparing %s session_id=%s wallet_id=%s protocol=%s threshold=%d participants=%d\n",
		kind,
		session.SessionID,
		session.WalletID,
		session.Protocol,
		session.Threshold,
		len(session.Participants),
	)
	for i, participant := range session.Participants {
		fmt.Printf(
			"participant[%d] id=%s type=%s pubkey_len=%d\n",
			i,
			participant.ID,
			participant.ParticipantType,
			len(participant.IdentityPublicKeyHex),
		)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
