// VulcanizeDB
// Copyright © 2022 Vulcanize

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

package debug

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth"
)

var _ tracers.Backend = &Backend{}

var (
	errMethodNotSupported = errors.New("backend method not supported")
)

// Backend implements tracers.Backend interface
type Backend struct {
	eth.Backend
}

// StateAtBlock retrieves the state database associated with a certain block
// We can't sub in our ipld-eth-statedb here because to match the expected interface we need to return *state.StateDB not vm.StateDB
func (b *Backend) StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, checkLive, preferDisk bool) (*state.StateDB, error) {
	rpcBlockNumber := rpc.BlockNumber(block.NumberU64())
	statedb, _, err := b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithNumber(rpcBlockNumber))
	return statedb, err
}

// StateAtTransaction returns the execution environment of a certain transaction
func (b *Backend) StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (core.Message, vm.BlockContext, *state.StateDB, error) {
	return nil, vm.BlockContext{}, nil, errMethodNotSupported
}
