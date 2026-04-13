package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
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
	Batch    BatchConfig            `json:"batch,omitempty"`
	Keygen   *rbtypes.KeygenRequest `json:"keygen,omitempty"`
	Sign     *rbtypes.SignRequest   `json:"sign,omitempty"`
}

type BatchConfig struct {
	Count        int    `json:"count,omitempty"`
	WalletPrefix string `json:"wallet_prefix,omitempty"`
	WalletStart  int    `json:"wallet_start,omitempty"`
	Concurrency  int    `json:"concurrency,omitempty"`
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
	fmt.Printf("loaded config path=%s nats_url=%s client_id=%s timeout=%s\n", *configPath, cfg.NATSURL, cfg.ClientID, cfg.Timeout)

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		exitf("connect nats: %v", err)
	}
	defer nc.Close()
	fmt.Printf("connected to nats url=%s\n", cfg.NATSURL)

	client := rbclient.New(rbclient.Options{
		NATSConn: nc,
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
		runKeygen(client, cfg.Keygen, cfg.Batch, timeout)
	case cfg.Sign != nil:
		runSign(client, cfg.Sign, cfg.Batch, timeout)
	default:
		exitf("config must contain either keygen or sign")
	}
}

func runKeygen(client rbclient.Client, req *rbtypes.KeygenRequest, batch BatchConfig, timeout time.Duration) {
	requests := buildKeygenRequests(*req, batch)
	wait := make(chan rbtypes.KeygenResult, len(requests))
	if err := client.OnKeygenResult(func(result rbtypes.KeygenResult) {
		fmt.Printf("received keygen callback session_id=%s result_type=%s\n", result.SessionID, result.ResultType)
		wait <- result
	}); err != nil {
		exitf("subscribe keygen result: %v", err)
	}
	fmt.Printf("subscribed keygen result requests=%d listener ready\n", len(requests))

	if len(requests) == 1 {
		logSession("keygen", requests[0].Session)
		if err := client.CreateKeygen(requests[0]); err != nil {
			exitf("create keygen: %v", err)
		}
		fmt.Printf("sent keygen request session_id=%s wallet_id=%s\n", requests[0].Session.SessionID, requests[0].Session.WalletID)
		select {
		case result := <-wait:
			printJSON(result)
		case <-time.After(timeout):
			exitf("timed out waiting for keygen result")
		}
		return
	}

	sendKeygenBatch(client, requests, batch)
	collectKeygenBatchResults(requests, wait, timeout)
}

func runSign(client rbclient.Client, req *rbtypes.SignRequest, batch BatchConfig, timeout time.Duration) {
	requests := buildSignRequests(*req, batch)
	wait := make(chan rbtypes.SignResult, len(requests))
	if err := client.OnSignResult(func(result rbtypes.SignResult) {
		fmt.Printf("received sign callback session_id=%s result_type=%s\n", result.SessionID, result.ResultType)
		wait <- result
	}); err != nil {
		exitf("subscribe sign result: %v", err)
	}
	fmt.Printf("subscribed sign result requests=%d listener ready\n", len(requests))

	if len(requests) == 1 {
		logSession("sign", requests[0].Session)
		fmt.Printf("signer_indexes=%v message_digest_len=%d\n", requests[0].SignerIndexes, len(requests[0].MessageDigestHex))
		if err := client.Sign(requests[0]); err != nil {
			exitf("sign: %v", err)
		}
		fmt.Printf("sent sign request session_id=%s wallet_id=%s signers=%v\n", requests[0].Session.SessionID, requests[0].Session.WalletID, requests[0].SignerIndexes)
		select {
		case result := <-wait:
			printJSON(result)
		case <-time.After(timeout):
			exitf("timed out waiting for sign result")
		}
		return
	}

	sendSignBatch(client, requests, batch)
	collectSignBatchResults(requests, wait, timeout)
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
	if cfg.Batch.Count <= 0 {
		cfg.Batch.Count = 1
	}
	if cfg.Batch.Concurrency <= 0 {
		cfg.Batch.Concurrency = cfg.Batch.Count
	}
	return &cfg, nil
}

func buildKeygenRequests(base rbtypes.KeygenRequest, batch BatchConfig) []rbtypes.KeygenRequest {
	requests := make([]rbtypes.KeygenRequest, 0, batch.Count)
	for i := 0; i < batch.Count; i++ {
		req := base
		req.Session.Operation = rbtypes.OperationKeygen
		req.Session.WalletID = batchWalletID(base.Session.WalletID, batch, i)
		req.Session.SessionID = uuid.NewString()
		requests = append(requests, req)
	}
	return requests
}

func buildSignRequests(base rbtypes.SignRequest, batch BatchConfig) []rbtypes.SignRequest {
	requests := make([]rbtypes.SignRequest, 0, batch.Count)
	for i := 0; i < batch.Count; i++ {
		req := base
		req.Session.Operation = rbtypes.OperationSign
		req.Session.WalletID = batchWalletID(base.Session.WalletID, batch, i)
		req.Session.SessionID = uuid.NewString()
		requests = append(requests, req)
	}
	return requests
}

func batchWalletID(baseWalletID string, batch BatchConfig, index int) string {
	if batch.Count <= 1 {
		return baseWalletID
	}
	prefix := strings.TrimSpace(batch.WalletPrefix)
	if prefix == "" {
		prefix = inferWalletPrefix(baseWalletID)
	}
	return prefix + strconv.Itoa(batch.WalletStart+index)
}

func inferWalletPrefix(baseWalletID string) string {
	baseWalletID = strings.TrimSpace(baseWalletID)
	if baseWalletID == "" {
		return "wallet-"
	}
	end := len(baseWalletID)
	for end > 0 && baseWalletID[end-1] >= '0' && baseWalletID[end-1] <= '9' {
		end--
	}
	if end == len(baseWalletID) {
		return baseWalletID + "-"
	}
	return baseWalletID[:end]
}

func sendKeygenBatch(client rbclient.Client, requests []rbtypes.KeygenRequest, batch BatchConfig) {
	runWithConcurrency(len(requests), batch.Concurrency, func(i int) {
		req := requests[i]
		logSession("keygen", req.Session)
		if err := client.CreateKeygen(req); err != nil {
			exitf("create keygen wallet_id=%s session_id=%s: %v", req.Session.WalletID, req.Session.SessionID, err)
		}
		fmt.Printf("sent keygen request session_id=%s wallet_id=%s\n", req.Session.SessionID, req.Session.WalletID)
	})
}

func sendSignBatch(client rbclient.Client, requests []rbtypes.SignRequest, batch BatchConfig) {
	runWithConcurrency(len(requests), batch.Concurrency, func(i int) {
		req := requests[i]
		logSession("sign", req.Session)
		fmt.Printf("signer_indexes=%v message_digest_len=%d\n", req.SignerIndexes, len(req.MessageDigestHex))
		if err := client.Sign(req); err != nil {
			exitf("sign wallet_id=%s session_id=%s: %v", req.Session.WalletID, req.Session.SessionID, err)
		}
		fmt.Printf("sent sign request session_id=%s wallet_id=%s signers=%v\n", req.Session.SessionID, req.Session.WalletID, req.SignerIndexes)
	})
}

func collectKeygenBatchResults(requests []rbtypes.KeygenRequest, wait <-chan rbtypes.KeygenResult, timeout time.Duration) {
	pending := make(map[string]rbtypes.KeygenRequest, len(requests))
	for _, req := range requests {
		pending[req.Session.SessionID] = req
	}
	deadline := time.After(timeout)
	results := make([]rbtypes.KeygenResult, 0, len(requests))
	for len(pending) > 0 {
		select {
		case result := <-wait:
			if _, ok := pending[result.SessionID]; !ok {
				continue
			}
			delete(pending, result.SessionID)
			results = append(results, result)
		case <-deadline:
			exitf("timed out waiting for keygen results pending=%d", len(pending))
		}
	}
	printJSON(results)
}

func collectSignBatchResults(requests []rbtypes.SignRequest, wait <-chan rbtypes.SignResult, timeout time.Duration) {
	pending := make(map[string]rbtypes.SignRequest, len(requests))
	for _, req := range requests {
		pending[req.Session.SessionID] = req
	}
	deadline := time.After(timeout)
	results := make([]rbtypes.SignResult, 0, len(requests))
	for len(pending) > 0 {
		select {
		case result := <-wait:
			if _, ok := pending[result.SessionID]; !ok {
				continue
			}
			delete(pending, result.SessionID)
			results = append(results, result)
		case <-deadline:
			exitf("timed out waiting for sign results pending=%d", len(pending))
		}
	}
	printJSON(results)
}

func runWithConcurrency(total, concurrency int, fn func(i int)) {
	if concurrency <= 0 || concurrency > total {
		concurrency = total
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(idx)
		}(i)
	}
	wg.Wait()
}

func printJSON(value any) {
	blob, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		exitf("marshal result: %v", err)
	}
	fmt.Println(string(blob))
}

func logSession(kind string, session rbtypes.SessionContext) {
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
