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

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	v "github.com/vulcanize/ipld-eth-server/version"
)

// APIName is the namespace used for the state diffing service API
const APIName = "vdb"

// APIVersion is the version of the state diffing service API
const APIVersion = "0.0.1"

// PublicServerAPI is the public api for the watcher
type PublicServerAPI struct {
	w Server
}

// NewPublicServerAPI creates a new PublicServerAPI with the provided underlying Server process
func NewPublicServerAPI(w Server) *PublicServerAPI {
	return &PublicServerAPI{
		w: w,
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

// Chain returns the chain type that this watcher instance supports
func (api *PublicServerAPI) Chain() shared.ChainType {
	return shared.Ethereum
}

// Struct for holding watcher meta data
type InfoAPI struct{}

// NewInfoAPI creates a new InfoAPI
func NewInfoAPI() *InfoAPI {
	return &InfoAPI{}
}

// Modules returns modules supported by this api
func (iapi *InfoAPI) Modules() map[string]string {
	return map[string]string{
		"vdb": "Stream",
	}
}

// NodeInfo gathers and returns a collection of metadata for the watcher
func (iapi *InfoAPI) NodeInfo() *p2p.NodeInfo {
	return &p2p.NodeInfo{
		// TODO: formalize this
		ID:   "vulcanizeDB",
		Name: "ipld-eth-server",
	}
}

// Version returns the version of the watcher
func (iapi *InfoAPI) Version() string {
	return v.VersionWithMeta
}
