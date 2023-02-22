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
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff/types"
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

// WatchAddress makes a geth WatchAddress API call with the given operation and args
func (api *PublicServerAPI) WatchAddress(operation types.OperationType, args []types.WatchAddressArg) error {
	err := api.rpc.Call(nil, "statediff_watchAddress", operation, args)
	if err != nil {
		return err
	}

	return nil
}
