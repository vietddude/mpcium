package eventconsumer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc/session"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

func (ec *eventConsumer) handleKeyGenerationEvent(ctx context.Context, walletID string) error {

	successEvent := &event.KeygenSuccessEvent{WalletID: walletID}
	var wg sync.WaitGroup

	// Start ECDSA and EDDSA sessions
	for _, keyType := range []types.KeyType{types.KeyTypeSecp256k1} {
		kgSession, err := ec.node.CreateKeygenSession(
			keyType,
			walletID,
			ec.mpcThreshold,
			ec.genKeySucecssQueue,
		)
		if err != nil {
			return fmt.Errorf("create %v session: %w", keyType, err)
		}

		defer kgSession.Close()

		kgSession.Listen()
		err = kgSession.WaitReady(ctx)
		if err != nil {
			return fmt.Errorf("wait for session ready: %w", err)
		}
		wg.Add(1)

		go func(s session.Session, kt types.KeyType) {
			defer wg.Done()

			s.StartKeygen(ctx, s.Send, func(data []byte) {
				err := s.SaveKey(
					ec.node.GetReadyPeersIncludeSelf(),
					ec.mpcThreshold,
					DefaultVersion,
					data,
				)
				if err != nil {
					logger.Error("Failed to save key", err)
				}
				logger.Info(
					"Saved key",
					"type",
					kt,
					"walletID",
					walletID,
					"threshold",
					ec.mpcThreshold,
					"version",
					DefaultVersion,
					"data",
					len(data),
				)
				if pubKey, err := s.GetPublicKey(data); err == nil {
					switch kt {
					case types.KeyTypeSecp256k1:
						successEvent.ECDSAPubKey = pubKey
					case types.KeyTypeEd25519:
						successEvent.EDDSAPubKey = pubKey
					}
				}
			})

			if err != nil {
				logger.Error("Keygen failed", err, "keyType", kt)
			}
		}(kgSession, keyType)
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-ctx.Done():
		logger.Warn("Keygen timed out", "walletID", walletID)
		return ctx.Err()
	case <-doneCh:
		// All keygens done
	}

	successBytes, err := json.Marshal(successEvent)
	if err != nil {
		return fmt.Errorf("marshal keygen error: %w", err)
	}

	err = ec.genKeySucecssQueue.Enqueue(
		event.KeygenSuccessEventTopic,
		successBytes,
		&messaging.EnqueueOptions{
			IdempotententKey: fmt.Sprintf(event.TypeGenerateWalletSuccess, walletID),
		},
	)
	if err != nil {
		return fmt.Errorf("enqueue keygen error: %w", err)
	}

	logger.Info("[COMPLETED KEY GEN] Key generation completed successfully", "walletID", walletID)
	return nil
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		req := &keygenRequest{
			msg:        natMsg,
			retryCount: 0,
			timestamp:  time.Now(),
			order:      ec.keygenLimiter.GetNextOrder(),
		}
		if ec.keygenLimiter.Enqueue(*req) {
			logger.Info("Keygen message queued",
				"order", req.order,
				"msg", string(natMsg.Data),
				"queueSize", ec.keygenLimiter.QueueLen())
		} else {
			logger.Warn("Keygen queue full, rejecting message", "order", req.order)
			natMsg.Nak() // Negative acknowledgment to retry later
		}
	})

	if err != nil {
		return err
	}

	ec.keyGenerationSub = sub
	return nil
}
