package eth

import (
	"context"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/sirupsen/logrus"
	"github.com/vulcanize/ipld-eth-server/pkg/events"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	channelName = "postgraphile:header_cids"
)

func (api *PublicEthAPI) NewStateChanges(ctx context.Context, crit filters.FilterCriteria) (*rpc.Subscription, error) {
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return &rpc.Subscription{}, rpc.ErrNotificationsUnsupported
	}
	rpcSub := notifier.CreateSubscription()
	go func() {
		errChan := make(chan error)
		stateChanges := make(chan events.Payload)
		api.events.SubscribeStateChanges(ethereum.FilterQuery(crit), stateChanges, errChan)

		for {
			select {
			case s := <-stateChanges:
				notifier.Notify(rpcSub.ID, s)
			case <-rpcSub.Err():
				api.events.Close()
				return
			case <-notifier.Closed():
				api.events.Close()
				return
			case err := <- errChan:
				logrus.Errorf("error from NewStateChanges notifier: %v", err)
				return
			}
		}
	}()

	return rpcSub, nil
}
