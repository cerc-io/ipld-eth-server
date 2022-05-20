// VulcanizeDB
// Copyright © 2019 Vulcanize

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package serve

import (
	"context"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff/types"
	log "github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-server/v4/pkg/eth"
)

// APIName is the namespace used for the state diffing service API
const APIName = "vdb"

// APIVersion is the version of the state diffing service API
const APIVersion = "0.0.1"

// PublicServerAPI is the public api for the watcher
type PublicServerAPI struct {
	w   Server
	rpc *rpc.Client
}

// NewPublicServerAPI creates a new PublicServerAPI with the provided underlying Server process
func NewPublicServerAPI(w Server, client *rpc.Client) *PublicServerAPI {
	return &PublicServerAPI{
		w:   w,
		rpc: client,
	}
}

// Stream is the public method to setup a subscription that fires off IPLD payloads as they are processed
func (api *PublicServerAPI) Stream(ctx context.Context, params eth.SubscriptionSettings) (*rpc.Subscription, error) {
	// ensure that the RPC connection supports subscriptions
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return nil, rpc.ErrNotificationsUnsupported
	}

	// create subscription and start waiting for stream events
	rpcSub := notifier.CreateSubscription()

	go func() {
		// subscribe to events from the SyncPublishScreenAndServe service
		payloadChannel := make(chan SubscriptionPayload, PayloadChanBufferSize)
		quitChan := make(chan bool, 1)
		go api.w.Subscribe(rpcSub.ID, payloadChannel, quitChan, params)

		// loop and await payloads and relay them to the subscriber using notifier
		for {
			select {
			case packet := <-payloadChannel:
				if err := notifier.Notify(rpcSub.ID, packet); err != nil {
					log.Error("Failed to send watcher data packet", "err", err)
					api.w.Unsubscribe(rpcSub.ID)
					return
				}
			case <-rpcSub.Err():
				api.w.Unsubscribe(rpcSub.ID)
				return
			case <-quitChan:
				// don't need to unsubscribe from the watcher, the service does so before sending the quit signal this way
				return
			}
		}
	}()

	return rpcSub, nil
}

// WatchAddress makes a geth WatchAddress API call with the given operation and args
func (api *PublicServerAPI) WatchAddress(operation types.OperationType, args []types.WatchAddressArg) error {
	err := api.rpc.Call(nil, "statediff_watchAddress", operation, args)
	if err != nil {
		return err
	}

	return nil
}
