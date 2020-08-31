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

package eth

import (
	"context"
	"math/big"

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// APIName is the namespace for the watcher's eth api
const APIName = "eth"

// APIVersion is the version of the watcher's eth api
const APIVersion = "0.0.1"

type PublicEthAPI struct {
	B *Backend
}

// NewPublicEthAPI creates a new PublicEthAPI with the provided underlying Backend
func NewPublicEthAPI(b *Backend) *PublicEthAPI {
	return &PublicEthAPI{
		B: b,
	}
}

// BlockNumber returns the block number of the chain head.
func (pea *PublicEthAPI) BlockNumber() hexutil.Uint64 {
	number, _ := pea.B.Retriever.RetrieveLastBlockNumber()
	return hexutil.Uint64(number)
}

// GetLogs returns logs matching the given argument that are stored within the state.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getlogs
func (pea *PublicEthAPI) GetLogs(ctx context.Context, crit ethereum.FilterQuery) ([]*types.Log, error) {
	// Convert FilterQuery into ReceiptFilter
	addrStrs := make([]string, len(crit.Addresses))
	for i, addr := range crit.Addresses {
		addrStrs[i] = addr.String()
	}
	topicStrSets := make([][]string, 4)
	for i, topicSet := range crit.Topics {
		if i > 3 {
			// don't allow more than 4 topics
			break
		}
		for _, topic := range topicSet {
			topicStrSets[i] = append(topicStrSets[i], topic.String())
		}
	}
	filter := ReceiptFilter{
		LogAddresses: addrStrs,
		Topics:       topicStrSets,
	}

	// Begin tx
	tx, err := pea.B.DB.Beginx()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(tx)
		} else {
			err = tx.Commit()
		}
	}()

	// If we have a blockhash to filter on, fire off single retrieval query
	if crit.BlockHash != nil {
		rctCIDs, err := pea.B.Retriever.RetrieveRctCIDs(tx, filter, 0, crit.BlockHash, nil)
		if err != nil {
			return nil, err
		}
		rctIPLDs, err := pea.B.Fetcher.FetchRcts(tx, rctCIDs)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return extractLogsOfInterest(rctIPLDs, filter.Topics)
	}
	// Otherwise, create block range from criteria
	// nil values are filled in; to request a single block have both ToBlock and FromBlock equal that number
	startingBlock := crit.FromBlock
	endingBlock := crit.ToBlock
	if startingBlock == nil {
		startingBlockInt, err := pea.B.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
		startingBlock = big.NewInt(startingBlockInt)
	}
	if endingBlock == nil {
		endingBlockInt, err := pea.B.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
		endingBlock = big.NewInt(endingBlockInt)
	}
	start := startingBlock.Int64()
	end := endingBlock.Int64()
	allRctCIDs := make([]eth.ReceiptModel, 0)
	for i := start; i <= end; i++ {
		rctCIDs, err := pea.B.Retriever.RetrieveRctCIDs(tx, filter, i, nil, nil)
		if err != nil {
			return nil, err
		}
		allRctCIDs = append(allRctCIDs, rctCIDs...)
	}
	rctIPLDs, err := pea.B.Fetcher.FetchRcts(tx, allRctCIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	logs, err := extractLogsOfInterest(rctIPLDs, filter.Topics)
	return logs, err // need to return err variable so that we return the err = tx.Commit() assignment in the defer
}

// GetHeaderByNumber returns the requested canonical block header.
// * When blockNr is -1 the chain head is returned.
// * We cannot support pending block calls since we do not have an active miner
func (pea *PublicEthAPI) GetHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (map[string]interface{}, error) {
	header, err := pea.B.HeaderByNumber(ctx, number)
	if header != nil && err == nil {
		return pea.rpcMarshalHeader(header)
	}
	return nil, err
}

// GetBlockByNumber returns the requested canonical block.
// * When blockNr is -1 the chain head is returned.
// * We cannot support pending block calls since we do not have an active miner
// * When fullTx is true all transactions in the block are returned, otherwise
//   only the transaction hash is returned.
func (pea *PublicEthAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := pea.B.BlockByNumber(ctx, number)
	if block != nil && err == nil {
		return pea.rpcMarshalBlock(block, true, fullTx)
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (pea *PublicEthAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := pea.B.BlockByHash(ctx, hash)
	if block != nil {
		return pea.rpcMarshalBlock(block, true, fullTx)
	}
	return nil, err
}

// GetTransactionByHash returns the transaction for the given hash
// eth ipld-eth-server cannot currently handle pending/tx_pool txs
func (pea *PublicEthAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	// Try to return an already finalized transaction
	tx, blockHash, blockNumber, index, err := pea.B.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		return NewRPCTransaction(tx, blockHash, blockNumber, index), nil
	}
	// Transaction unknown, return as such
	return nil, nil
}
