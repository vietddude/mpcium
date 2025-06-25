package party

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
)

type Party interface {
	StartKeygen(ctx context.Context, send func(tss.Message), onComplete func([]byte))
	StartSigning(ctx context.Context, msg *big.Int, send func(tss.Message), onComplete func([]byte))
	StartResharing(
		ctx context.Context,
		oldPartyIDs,
		newPartyIDs []*tss.PartyID,
		oldThreshold,
		newThreshold int,
		send func(tss.Message),
		onComplete func([]byte),
	)

	PartyID() *tss.PartyID
	PartyIDs() []*tss.PartyID
	GetSaveData() []byte
	SetSaveData(saveData []byte)
	ClassifyMsg(msgBytes []byte) (uint8, bool, error)
	InCh() chan types.TssMessage
	OutCh() chan tss.Message
	ErrCh() chan error
	Close()
}

type party struct {
	walletID  string
	threshold int
	partyID   *tss.PartyID
	partyIDs  []*tss.PartyID
	inCh      chan types.TssMessage
	outCh     chan tss.Message
	errCh     chan error
}

func NewParty(
	walletID string,
	partyID *tss.PartyID,
	partyIDs []*tss.PartyID,
	threshold int,
	errCh chan error,
) *party {
	inCh := make(chan types.TssMessage, 1000)
	outCh := make(chan tss.Message, 1000)
	return &party{walletID, threshold, partyID, partyIDs, inCh, outCh, errCh}
}

func (p *party) PartyID() *tss.PartyID {
	return p.partyID
}

func (p *party) PartyIDs() []*tss.PartyID {
	return p.partyIDs
}

func (p *party) InCh() chan types.TssMessage {
	return p.inCh
}

func (p *party) OutCh() chan tss.Message {
	return p.outCh
}

func (p *party) ErrCh() chan error {
	return p.errCh
}

func (p *party) Close() {
	close(p.inCh)
	close(p.outCh)
}

// runParty handles the common party execution loop
func runParty[T any](
	s Party,
	ctx context.Context,
	party tss.Party,
	send func(tss.Message),
	endCh chan T,
	onComplete func([]byte),
) {
	// Start the party in a goroutine to handle errors
	go func() {
		logger.Info("Starting party", "partyID", s.PartyID().String())
		if err := party.Start(); err != nil {
			s.ErrCh() <- err
			return
		}
	}()

	// Main message handling loop
	for {
		select {
		case <-ctx.Done():
			return
		case in := <-s.InCh():
			ok, err := party.UpdateFromBytes(in.MsgBytes, in.From, in.IsBroadcast)
			if !ok || err != nil {
				s.ErrCh() <- err
				return
			}
		case out := <-s.OutCh():
			send(out)
		case result := <-endCh:
			bytes, err := json.Marshal(result)
			if err != nil {
				s.ErrCh() <- err
				return
			}
			onComplete(bytes)
			return
		}
	}
}
