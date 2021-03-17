package eth

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth/filters"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	channelName = "channelName"
)

func (api *PublicEthAPI) NewStateChanges(ctx context.Context, crit filters.FilterCriteria) (*rpc.Subscription, error) {
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return &rpc.Subscription{}, rpc.ErrNotificationsUnsupported
	}

	rpcSub := notifier.CreateSubscription()

	go func() {
		stateChanges := make(chan Payload)
		stateChangeSub := api.events.SubscribeStateChanges(ethereum.FilterQuery(crit), stateChanges)

		for {
			select {
			case s := <-stateChanges:
				notifier.Notify(rpcSub.ID, s)
			case <-rpcSub.Err():
				stateChangeSub.Unsubscribe()
				return
			case <-notifier.Closed():
				stateChangeSub.Unsubscribe()
				return
			}
		}
	}()

	return rpcSub, nil
}

// Payload packages the data to send to statediff subscriptions
type Payload struct {
	StateDiffRlp []byte `json:"stateDiff"    gencodec:"required"`
}

// StateDiff is the final output structure from the builder
type StateDiff struct {
	BlockNumber     *big.Int      `json:"blockNumber"     gencodec:"required"`
	BlockHash       common.Hash   `json:"blockHash"       gencodec:"required"`
	UpdatedAccounts []AccountDiff `json:"updatedAccounts" gencodec:"required"`
}

// AccountDiff holds the data for a single state diff node
type AccountDiff struct {
	Key     []byte        `json:"key"         gencodec:"required"`
	Value   []byte        `json:"value"       gencodec:"required"`
	Storage []StorageDiff `json:"storage"     gencodec:"required"`
}

// StorageDiff holds the data for a single storage diff node
type StorageDiff struct {
	Key   []byte `json:"key"         gencodec:"required"`
	Value []byte `json:"value"       gencodec:"required"`
}
