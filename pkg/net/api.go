// VulcanizeDB
// Copyright © 2021 Vulcanize

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

package net

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// APIName is the namespace for the watcher's eth api
const APIName = "net"

// APIVersion is the version of the watcher's eth api
const APIVersion = "0.0.1"

// PublicNetAPI is the net nampespace API
type PublicNetAPI struct {
	// Proxy node for forwarding cache misses
	networkVersion uint64
	rpc            *rpc.Client
	ethClient      *ethclient.Client
}

// NewPublicNetAPI creates a new PublicNetAPI with the provided underlying Backend
func NewPublicNetAPI(networkID uint64, client *rpc.Client) *PublicNetAPI {
	var ethClient *ethclient.Client
	if client != nil {
		ethClient = ethclient.NewClient(client)
	}
	return &PublicNetAPI{
		networkVersion: networkID,
		rpc:            client,
		ethClient:      ethClient,
	}
}

// Listening returns an indication if the node is listening for network connections.
func (pna *PublicNetAPI) Listening() bool {
	// in this case it is actually whether or not the proxied node is listening
	if pna.rpc != nil {
		var listening bool
		if err := pna.rpc.Call(&listening, "net_listening"); err == nil {
			return listening
		}
	}
	return false
}

// PeerCount returns the number of connected peers
func (pna *PublicNetAPI) PeerCount() hexutil.Uint {
	// in this case it is actually the peer count of the proxied node
	if pna.rpc != nil {
		var num hexutil.Uint
		if err := pna.rpc.Call(&num, "net_peerCount"); err == nil {
			return num
		}
	}
	return hexutil.Uint(0)
}

// Version returns the current ethereum protocol version.
func (pna *PublicNetAPI) Version() string {
	if pna.networkVersion != 0 {
		return fmt.Sprintf("%d", pna.networkVersion)
	}
	if pna.rpc != nil {
		var version string
		if err := pna.rpc.Call(&version, "net_version"); err == nil {
			return version
		}
	}
	return ""
}
