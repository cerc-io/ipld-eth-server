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

// Client is used by watchers to stream chain IPLD data from a vulcanizedb ipld-eth-server
package client

import (
	"context"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/vulcanize/ipld-eth-server/pkg/watch"
)

// Client is used to subscribe to the ipld-eth-server ipld data stream
type Client struct {
	c *rpc.Client
}

// NewClient creates a new Client
func NewClient(c *rpc.Client) *Client {
	return &Client{
		c: c,
	}
}

// Stream is the main loop for subscribing to iplds from an ipld-eth-server server
func (c *Client) Stream(payloadChan chan watch.SubscriptionPayload, rlpParams []byte) (*rpc.ClientSubscription, error) {
	return c.c.Subscribe(context.Background(), "vdb", payloadChan, "stream", rlpParams)
}
