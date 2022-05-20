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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-server/v4/pkg/shared"
)

// APIName is the namespace for the watcher's eth api
const APIName = "eth"

// APIVersion is the version of the watcher's eth api
const APIVersion = "0.0.1"

// PublicEthAPI is the eth namespace API
type PublicEthAPI struct {
	// Local db backend
	B *Backend

	// Proxy node for forwarding cache misses
	supportsStateDiff bool // Whether the remote node supports the statediff_writeStateDiffAt endpoint, if it does we can fill the local cache when we hit a miss
	rpc               *rpc.Client
	ethClient         *ethclient.Client
	forwardEthCalls   bool // if true, forward eth_call calls directly to the configured proxy node
	proxyOnError      bool // turn on regular proxy fall-through on errors; needed to test difference between direct and indirect fall-through
}

// NewPublicEthAPI creates a new PublicEthAPI with the provided underlying Backend
func NewPublicEthAPI(b *Backend, client *rpc.Client, supportsStateDiff, forwardEthCalls, proxyOnError bool) (*PublicEthAPI, error) {
	if forwardEthCalls && client == nil {
		return nil, errors.New("ipld-eth-server is configured to forward eth_calls to proxy node but no proxy node is configured")
	}
	if proxyOnError && client == nil {
		return nil, errors.New("ipld-eth-server is configured to forward all calls to proxy node on errors but no proxy node is configured")
	}
	var ethClient *ethclient.Client
	if client != nil {
		ethClient = ethclient.NewClient(client)
	}
	return &PublicEthAPI{
		B:                 b,
		supportsStateDiff: supportsStateDiff,
		rpc:               client,
		ethClient:         ethClient,
		forwardEthCalls:   forwardEthCalls,
		proxyOnError:      proxyOnError,
	}, nil
}

/*

Headers and blocks

*/

// GetHeaderByNumber returns the requested canonical block header.
// * When blockNr is -1 the chain head is returned.
// * We cannot support pending block calls since we do not have an active miner
func (pea *PublicEthAPI) GetHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (map[string]interface{}, error) {
	header, err := pea.B.HeaderByNumber(ctx, number)
	if header != nil && err == nil {
		return pea.rpcMarshalHeader(header)
	}
	if pea.proxyOnError {
		if header, err := pea.ethClient.HeaderByNumber(ctx, big.NewInt(number.Int64())); header != nil && err == nil {
			go pea.writeStateDiffAt(number.Int64())
			return pea.rpcMarshalHeader(header)
		}
	}

	return nil, err
}

// GetHeaderByHash returns the requested header by hash.
func (pea *PublicEthAPI) GetHeaderByHash(ctx context.Context, hash common.Hash) map[string]interface{} {
	header, err := pea.B.HeaderByHash(ctx, hash)
	if header != nil && err == nil {
		if res, err := pea.rpcMarshalHeader(header); err == nil {
			return res
		}
	}

	if pea.proxyOnError {
		if header, err := pea.ethClient.HeaderByHash(ctx, hash); header != nil && err == nil {
			go pea.writeStateDiffFor(hash)
			if res, err := pea.rpcMarshalHeader(header); err != nil {
				return res
			}
		}
	}

	return nil
}

// rpcMarshalHeader uses the generalized output filler, then adds the total difficulty field
func (pea *PublicEthAPI) rpcMarshalHeader(header *types.Header) (map[string]interface{}, error) {
	fields := RPCMarshalHeader(header)
	td, err := pea.B.GetTd(header.Hash())
	if err != nil {
		return nil, err
	}

	fields["totalDifficulty"] = (*hexutil.Big)(td)

	return fields, nil
}

// BlockNumber returns the block number of the chain head.
func (pea *PublicEthAPI) BlockNumber() hexutil.Uint64 {
	number, _ := pea.B.Retriever.RetrieveLastBlockNumber()
	return hexutil.Uint64(number)
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

	if pea.proxyOnError {
		if block, err := pea.ethClient.BlockByNumber(ctx, big.NewInt(number.Int64())); block != nil && err == nil {
			go pea.writeStateDiffAt(number.Int64())
			return pea.rpcMarshalBlock(block, true, fullTx)
		}
	}

	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (pea *PublicEthAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := pea.B.BlockByHash(ctx, hash)
	if block != nil && err == nil {
		return pea.rpcMarshalBlock(block, true, fullTx)
	}

	if pea.proxyOnError {
		if block, err := pea.ethClient.BlockByHash(ctx, hash); block != nil && err == nil {
			go pea.writeStateDiffFor(hash)
			return pea.rpcMarshalBlock(block, true, fullTx)
		}
	}

	return nil, err
}

// ChainId is the EIP-155 replay-protection chain id for the current ethereum chain config.
func (pea *PublicEthAPI) ChainId() (*hexutil.Big, error) {
	block, err := pea.B.CurrentBlock()
	if err != nil {
		if pea.proxyOnError {
			if id, err := pea.ethClient.ChainID(context.Background()); err == nil {
				return (*hexutil.Big)(id), nil
			}
		}
		return nil, err
	}

	if config := pea.B.Config.ChainConfig; config.IsEIP155(block.Number()) {
		return (*hexutil.Big)(config.ChainID), nil
	}
	return nil, fmt.Errorf("chain not synced beyond EIP-155 replay-protection fork block")
}

/*

Uncles

*/

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index. When fullTx is true
// all transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (pea *PublicEthAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := pea.B.BlockByNumber(ctx, blockNr)
	if block != nil && err == nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			logrus.Debugf("uncle with index %s request at block number %d was not found", index.String(), blockNr.Int64())
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return pea.rpcMarshalBlock(block, false, false)
	}

	if pea.proxyOnError {
		if uncle, uncleHashes, err := getBlockAndUncleHashes(pea.rpc, ctx, "eth_getUncleByBlockNumberAndIndex", blockNr, index); uncle != nil && err == nil {
			go pea.writeStateDiffAt(blockNr.Int64())
			return pea.rpcMarshalBlockWithUncleHashes(uncle, uncleHashes, false, false)
		}
	}

	return nil, err
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index. When fullTx is true
// all transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (pea *PublicEthAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := pea.B.BlockByHash(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			logrus.Debugf("uncle with index %s request at block hash %s was not found", index.String(), blockHash.Hex())
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return pea.rpcMarshalBlock(block, false, false)
	}

	if pea.proxyOnError {
		if uncle, uncleHashes, err := getBlockAndUncleHashes(pea.rpc, ctx, "eth_getUncleByBlockHashAndIndex", blockHash, index); uncle != nil && err == nil {
			go pea.writeStateDiffFor(blockHash)
			return pea.rpcMarshalBlockWithUncleHashes(uncle, uncleHashes, false, false)
		}
	}

	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
func (pea *PublicEthAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, err := pea.B.BlockByNumber(ctx, blockNr); block != nil && err == nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}

	if pea.proxyOnError {
		var num *hexutil.Uint
		if err := pea.rpc.CallContext(ctx, &num, "eth_getUncleCountByBlockNumber", blockNr); num != nil && err == nil {
			go pea.writeStateDiffAt(blockNr.Int64())
			return num
		}
	}

	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
func (pea *PublicEthAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, err := pea.B.BlockByHash(ctx, blockHash); block != nil && err == nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}

	if pea.proxyOnError {
		var num *hexutil.Uint
		if err := pea.rpc.CallContext(ctx, &num, "eth_getUncleCountByBlockHash", blockHash); num != nil && err == nil {
			go pea.writeStateDiffFor(blockHash)
			return num
		}
	}

	return nil
}

/*

Transactions

*/

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (pea *PublicEthAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	count, err := pea.localGetTransactionCount(ctx, address, blockNrOrHash)
	if count != nil && err == nil {
		return count, nil
	}

	if pea.proxyOnError {
		var num *hexutil.Uint64
		if err := pea.rpc.CallContext(ctx, &num, "eth_getTransactionCount", address, blockNrOrHash); num != nil && err == nil {
			go pea.writeStateDiffAtOrFor(blockNrOrHash)
			return num, nil
		}
	}

	return nil, err
}

func (pea *PublicEthAPI) localGetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	account, err := pea.B.GetAccountByNumberOrHash(ctx, address, blockNrOrHash)
	if err != nil {
		return nil, err
	}

	nonce := hexutil.Uint64(account.Nonce)
	return &nonce, nil
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (pea *PublicEthAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := pea.B.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}

	if pea.proxyOnError {
		var num *hexutil.Uint
		if err := pea.rpc.CallContext(ctx, &num, "eth_getBlockTransactionCountByNumber", blockNr); num != nil && err == nil {
			go pea.writeStateDiffAt(blockNr.Int64())
			return num
		}
	}

	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
func (pea *PublicEthAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := pea.B.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}

	if pea.proxyOnError {
		var num *hexutil.Uint
		if err := pea.rpc.CallContext(ctx, &num, "eth_getBlockTransactionCountByHash", blockHash); num != nil && err == nil {
			go pea.writeStateDiffFor(blockHash)
			return num
		}
	}

	return nil
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
func (pea *PublicEthAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := pea.B.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}

	if pea.proxyOnError {
		var tx *RPCTransaction
		if err := pea.rpc.CallContext(ctx, &tx, "eth_getTransactionByBlockNumberAndIndex", blockNr, index); tx != nil && err == nil {
			go pea.writeStateDiffAt(blockNr.Int64())
			return tx
		}
	}

	return nil
}

// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
func (pea *PublicEthAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := pea.B.BlockByHash(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}

	if pea.proxyOnError {
		var tx *RPCTransaction
		if err := pea.rpc.CallContext(ctx, &tx, "eth_getTransactionByBlockHashAndIndex", blockHash, index); tx != nil && err == nil {
			go pea.writeStateDiffFor(blockHash)
			return tx
		}
	}

	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the transaction for the given block number and index.
func (pea *PublicEthAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := pea.B.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	if pea.proxyOnError {
		var tx hexutil.Bytes
		if err := pea.rpc.CallContext(ctx, &tx, "eth_getRawTransactionByBlockNumberAndIndex", blockNr, index); tx != nil && err == nil {
			go pea.writeStateDiffAt(blockNr.Int64())
			return tx
		}
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the transaction for the given block hash and index.
func (pea *PublicEthAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := pea.B.BlockByHash(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	if pea.proxyOnError {
		var tx hexutil.Bytes
		if err := pea.rpc.CallContext(ctx, &tx, "eth_getRawTransactionByBlockHashAndIndex", blockHash, index); tx != nil && err == nil {
			go pea.writeStateDiffFor(blockHash)
			return tx
		}
	}
	return nil
}

// GetTransactionByHash returns the transaction for the given hash
// eth ipld-eth-server cannot currently handle pending/tx_pool txs
func (pea *PublicEthAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	tx, blockHash, blockNumber, index, err := pea.B.GetTransaction(ctx, hash)
	if tx != nil && err == nil {
		header, err := pea.B.HeaderByHash(ctx, blockHash)
		if err != nil {
			return nil, err
		}

		return NewRPCTransaction(tx, blockHash, blockNumber, index, header.BaseFee), nil
	}
	if pea.proxyOnError {
		var tx *RPCTransaction
		if err := pea.rpc.CallContext(ctx, &tx, "eth_getTransactionByHash", hash); tx != nil && err == nil {
			go pea.writeStateDiffFor(hash)
			return tx, nil
		}
	}
	return nil, err
}

// GetRawTransactionByHash returns the bytes of the transaction for the given hash.
func (pea *PublicEthAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	tx, _, _, _, err := pea.B.GetTransaction(ctx, hash)
	if tx != nil && err == nil {
		return rlp.EncodeToBytes(tx)
	}
	if pea.proxyOnError {
		var tx hexutil.Bytes
		if err := pea.rpc.CallContext(ctx, &tx, "eth_getRawTransactionByHash", hash); tx != nil && err == nil {
			go pea.writeStateDiffFor(hash)
			return tx, nil
		}
	}
	return nil, err
}

/*

Receipts and Logs

*/

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
func (pea *PublicEthAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	receipt, err := pea.localGetTransactionReceipt(ctx, hash)
	if receipt != nil && err == nil {
		return receipt, nil
	}
	if pea.proxyOnError {
		if receipt := pea.remoteGetTransactionReceipt(ctx, hash); receipt != nil {
			go pea.writeStateDiffFor(hash)
			return receipt, nil
		}
	}
	return nil, err
}

func (pea *PublicEthAPI) localGetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	// TODO: this can be optimized for Postgres
	tx, blockHash, blockNumber, index, err := pea.B.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, nil
	}
	receipts, err := pea.B.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	block, err := pea.B.BlockByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	err = receipts.DeriveFields(pea.B.Config.ChainConfig, blockHash, blockNumber, block.Transactions())
	if err != nil {
		return nil, err
	}
	if len(receipts) <= int(index) {
		return nil, nil
	}
	receipt := receipts[index]

	var signer types.Signer = types.FrontierSigner{}
	if tx.Protected() {
		signer = types.NewEIP155Signer(tx.ChainId())
	}
	from, _ := types.Sender(signer, tx)

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(index),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
	}

	// Assign receipt status or post state.
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = []*types.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields, nil
}

func (pea *PublicEthAPI) remoteGetTransactionReceipt(ctx context.Context, hash common.Hash) map[string]interface{} {
	var rct *RPCReceipt
	if err := pea.rpc.CallContext(ctx, &rct, "eth_getTransactionReceipt", hash); rct != nil && err == nil {
		return map[string]interface{}{
			"blockHash":         rct.BlockHash,
			"blockNumber":       rct.BlockNumber,
			"transactionHash":   rct.TransactionHash,
			"transactionIndex":  rct.TransactionIndex,
			"from":              rct.From,
			"to":                rct.To,
			"gasUsed":           rct.GasUsed,
			"cumulativeGasUsed": rct.CumulativeGsUsed,
			"contractAddress":   rct.ContractAddress,
			"logs":              rct.Logs,
			"logsBloom":         rct.Bloom,
			"root":              rct.Root,
			"status":            rct.Status,
		}
	}
	return nil
}

// GetLogs returns logs matching the given argument that are stored within the state.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getlogs
func (pea *PublicEthAPI) GetLogs(ctx context.Context, crit filters.FilterCriteria) ([]*types.Log, error) {
	logs, err := pea.localGetLogs(crit)
	if err != nil && pea.proxyOnError {
		var res []*types.Log
		if err := pea.rpc.CallContext(ctx, &res, "eth_getLogs", crit); err == nil {
			go pea.writeStateDiffWithCriteria(crit)
			return res, nil
		}
	}
	return logs, err
}

func (pea *PublicEthAPI) localGetLogs(crit filters.FilterCriteria) ([]*types.Log, error) {
	// TODO: this can be optimized away from using the old cid retriever and ipld fetcher interfaces
	// Convert FilterQuery into ReceiptFilter
	addrStrs := make([]string, len(crit.Addresses))
	for i, addr := range crit.Addresses {
		addrStrs[i] = addr.String()
	}

	topicStrSets := make([][]string, len(crit.Topics))
	for i, topicSet := range crit.Topics {
		if i > 3 {
			topicStrSets = topicStrSets[:4]
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

	// If we have a blockHash to filter on, fire off single retrieval query
	if crit.BlockHash != nil {
		filteredLogs, err := pea.B.Retriever.RetrieveFilteredLog(tx, filter, 0, crit.BlockHash)
		if err != nil {
			return nil, err
		}

		return decomposeLogs(filteredLogs)
	}

	// Otherwise, create block range from criteria
	// nil values are filled in; to request a single block have both ToBlock and FromBlock equal that number
	startingBlock := crit.FromBlock
	endingBlock := crit.ToBlock
	if startingBlock == nil {
		startingBlock = common.Big0
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
	var logs []*types.Log
	for i := start; i <= end; i++ {
		filteredLogs, err := pea.B.Retriever.RetrieveFilteredLog(tx, filter, i, nil)
		if err != nil {
			return nil, err
		}

		logCIDs, err := decomposeLogs(filteredLogs)
		if err != nil {
			return nil, err
		}

		logs = append(logs, logCIDs...)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return logs, err // need to return err variable so that we return the err = tx.Commit() assignment in the defer
}

/*

State and Storage

*/

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (pea *PublicEthAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	bal, err := pea.localGetBalance(ctx, address, blockNrOrHash)
	if bal != nil && err == nil {
		return bal, nil
	}
	if pea.proxyOnError {
		var res *hexutil.Big
		if err := pea.rpc.CallContext(ctx, &res, "eth_getBalance", address, blockNrOrHash); res != nil && err == nil {
			go pea.writeStateDiffAtOrFor(blockNrOrHash)
			return res, nil
		}
	}
	if err == sql.ErrNoRows {
		return (*hexutil.Big)(big.NewInt(0)), nil
	}

	return nil, err
}

func (pea *PublicEthAPI) localGetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	account, err := pea.B.GetAccountByNumberOrHash(ctx, address, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(account.Balance), nil
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (pea *PublicEthAPI) GetStorageAt(ctx context.Context, address common.Address, key string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	storageVal, err := pea.B.GetStorageByNumberOrHash(ctx, address, common.HexToHash(key), blockNrOrHash)
	if storageVal != nil && err == nil {
		var value common.Hash
		_, content, _, err := rlp.Split(storageVal)
		if err == io.ErrUnexpectedEOF {
			return hexutil.Bytes{}, nil
		}
		if err != nil {
			return nil, err
		}
		value.SetBytes(content)

		return value[:], nil
	}
	if pea.proxyOnError {
		var res hexutil.Bytes
		if err := pea.rpc.CallContext(ctx, &res, "eth_getStorageAt", address, key, blockNrOrHash); res != nil && err == nil {
			go pea.writeStateDiffAtOrFor(blockNrOrHash)
			return res, nil
		}
	}
	if err == sql.ErrNoRows {
		return make([]byte, 32), nil
	}
	return nil, err
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (pea *PublicEthAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	code, err := pea.B.GetCodeByNumberOrHash(ctx, address, blockNrOrHash)
	if code != nil && err == nil {
		return code, nil
	}
	if pea.proxyOnError {
		var res hexutil.Bytes
		if err := pea.rpc.CallContext(ctx, &res, "eth_getCode", address, blockNrOrHash); res != nil && err == nil {
			go pea.writeStateDiffAtOrFor(blockNrOrHash)
			return res, nil
		}
	}
	if err == sql.ErrNoRows {
		return code, nil
	}

	return nil, err
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
func (pea *PublicEthAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	proof, err := pea.localGetProof(ctx, address, storageKeys, blockNrOrHash)
	if proof != nil && err == nil {
		return proof, nil
	}
	if pea.proxyOnError {
		var res *AccountResult
		if err := pea.rpc.CallContext(ctx, &res, "eth_getProof", address, storageKeys, blockNrOrHash); res != nil && err == nil {
			go pea.writeStateDiffAtOrFor(blockNrOrHash)
			return res, nil
		}
	}
	return nil, err
}

func (pea *PublicEthAPI) localGetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	state, _, err := pea.B.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	storageTrie := state.StorageTrie(address)
	storageHash := types.EmptyRootHash
	codeHash := state.GetCodeHash(address)
	storageProof := make([]StorageResult, len(storageKeys))

	// if we have a storageTrie, (which means the account exists), we can update the storagehash
	if storageTrie != nil {
		storageHash = storageTrie.Hash()
	} else {
		// no storageTrie means the account does not exist, so the codeHash is the hash of an empty bytearray.
		codeHash = crypto.Keccak256Hash(nil)
	}

	// create the proof for the storageKeys
	for i, key := range storageKeys {
		if storageTrie != nil {
			proof, storageError := state.GetStorageProof(address, common.HexToHash(key))
			if storageError != nil {
				return nil, storageError
			}
			storageProof[i] = StorageResult{key, (*hexutil.Big)(state.GetState(address, common.HexToHash(key)).Big()), toHexSlice(proof)}
		} else {
			storageProof[i] = StorageResult{key, &hexutil.Big{}, []string{}}
		}
	}

	// create the accountProof
	accountProof, proofErr := state.GetProof(address)
	if proofErr != nil {
		return nil, proofErr
	}

	return &AccountResult{
		Address:      address,
		AccountProof: toHexSlice(accountProof),
		Balance:      (*hexutil.Big)(state.GetBalance(address)),
		CodeHash:     codeHash,
		Nonce:        hexutil.Uint64(state.GetNonce(address)),
		StorageHash:  storageHash,
		StorageProof: storageProof,
	}, state.Error()
}

// revertError is an API error that encompassas an EVM revertal with JSON error
// code and a binary data blob.
type revertError struct {
	error
	reason string // revert reason hex encoded
}

// ErrorCode returns the JSON error code for a revertal.
// See: https://github.com/ethereum/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
func (e *revertError) ErrorCode() int {
	return 3
}

// ErrorData returns the hex encoded revert reason.
func (e *revertError) ErrorData() interface{} {
	return e.reason
}

func newRevertError(result *core.ExecutionResult) *revertError {
	reason, errUnpack := abi.UnpackRevert(result.Revert())
	err := errors.New("execution reverted")
	if errUnpack == nil {
		err = fmt.Errorf("execution reverted: %v", reason)
	}
	return &revertError{
		error:  err,
		reason: hexutil.Encode(result.Revert()),
	}
}

// OverrideAccount indicates the overriding fields of account during the execution
// of a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if statDiff is set, all diff will be applied first and then execute the call
// message.
type OverrideAccount struct {
	Nonce     *hexutil.Uint64              `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

// StateOverride is the collection of overridden accounts.
type StateOverride map[common.Address]OverrideAccount

// Apply overrides the fields of specified accounts into the given state.
func (diff *StateOverride) Apply(state *state.StateDB) error {
	if diff == nil {
		return nil
	}
	for addr, account := range *diff {
		// Override account nonce.
		if account.Nonce != nil {
			state.SetNonce(addr, uint64(*account.Nonce))
		}
		// Override account(contract) code.
		if account.Code != nil {
			state.SetCode(addr, *account.Code)
		}
		// Override account balance.
		if account.Balance != nil {
			state.SetBalance(addr, (*big.Int)(*account.Balance))
		}
		if account.State != nil && account.StateDiff != nil {
			return fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
		}
		// Replace entire state if caller requires.
		if account.State != nil {
			state.SetStorage(addr, *account.State)
		}
		// Apply state diff into specified accounts.
		if account.StateDiff != nil {
			for key, value := range *account.StateDiff {
				state.SetState(addr, key, value)
			}
		}
	}
	return nil
}

// Call executes the given transaction on the state for the given block number.
//
// Additionally, the caller can specify a batch of contract for fields overriding.
//
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
func (pea *PublicEthAPI) Call(ctx context.Context, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride) (hexutil.Bytes, error) {
	if pea.forwardEthCalls {
		var hex hexutil.Bytes
		err := pea.rpc.CallContext(ctx, &hex, "eth_call", args, blockNrOrHash, overrides)
		return hex, err
	}

	result, err := DoCall(ctx, pea.B, args, blockNrOrHash, overrides, 5*time.Second, pea.B.Config.RPCGasCap.Uint64())

	// If the result contains a revert reason, try to unpack and return it.
	if err == nil {
		if len(result.Revert()) > 0 {
			err = newRevertError(result)
		} else if result.Err != nil {
			err = result.Err
		}
	}

	if err != nil && pea.proxyOnError {
		var hex hexutil.Bytes
		if err := pea.rpc.CallContext(ctx, &hex, "eth_call", args, blockNrOrHash, overrides); hex != nil && err == nil {
			go pea.writeStateDiffAtOrFor(blockNrOrHash)
			return hex, nil
		}
	}
	return result.Return(), err
}

func DoCall(ctx context.Context, b *Backend, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	defer func(start time.Time) {
		logrus.Debugf("Executing EVM call finished %s runtime %s", time.Now().String(), time.Since(start).String())
	}(time.Now())

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	if err := overrides.Apply(state); err != nil {
		return nil, err
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return nil, err
	}

	evm, vmError, err := b.GetEVM(ctx, msg, state, header)
	if err != nil {
		return nil, err
	}

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.Gas())
	}
	return result, nil
}

// writeStateDiffAtOrFor calls out to the proxy statediffing geth client to fill in a gap in the index
func (pea *PublicEthAPI) writeStateDiffAtOrFor(blockNrOrHash rpc.BlockNumberOrHash) {
	// short circuit right away if the proxy doesn't support diffing
	if !pea.supportsStateDiff {
		return
	}
	if blockNr, ok := blockNrOrHash.Number(); ok {
		pea.writeStateDiffAt(blockNr.Int64())
		return
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		pea.writeStateDiffFor(hash)
	}
}

// writeStateDiffWithCriteria calls out to the proxy statediffing geth client to fill in a gap in the index
func (pea *PublicEthAPI) writeStateDiffWithCriteria(crit filters.FilterCriteria) {
	// short circuit right away if the proxy doesn't support diffing
	if !pea.supportsStateDiff {
		return
	}
	if crit.BlockHash != nil {
		pea.writeStateDiffFor(*crit.BlockHash)
		return
	}
	var start, end int64
	if crit.FromBlock != nil {
		start = crit.FromBlock.Int64()
	}
	if crit.ToBlock != nil {
		end = crit.ToBlock.Int64()
	} else {
		end = start
	}
	for i := start; i <= end; i++ {
		pea.writeStateDiffAt(i)
	}
}

// writeStateDiffAt calls out to the proxy statediffing geth client to fill in a gap in the index
func (pea *PublicEthAPI) writeStateDiffAt(height int64) {
	if !pea.supportsStateDiff {
		return
	}
	// we use a separate context than the one provided by the client
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	var data json.RawMessage
	params := statediff.Params{
		IntermediateStateNodes:   true,
		IntermediateStorageNodes: true,
		IncludeBlock:             true,
		IncludeReceipts:          true,
		IncludeTD:                true,
		IncludeCode:              true,
	}
	if err := pea.rpc.CallContext(ctx, &data, "statediff_writeStateDiffAt", uint64(height), params); err != nil {
		logrus.Errorf("writeStateDiffAt %d faild with err %s", height, err.Error())
	}
}

// writeStateDiffFor calls out to the proxy statediffing geth client to fill in a gap in the index
func (pea *PublicEthAPI) writeStateDiffFor(blockHash common.Hash) {
	if !pea.supportsStateDiff {
		return
	}
	// we use a separate context than the one provided by the client
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	var data json.RawMessage
	params := statediff.Params{
		IntermediateStateNodes:   true,
		IntermediateStorageNodes: true,
		IncludeBlock:             true,
		IncludeReceipts:          true,
		IncludeTD:                true,
		IncludeCode:              true,
	}
	if err := pea.rpc.CallContext(ctx, &data, "statediff_writeStateDiffFor", blockHash, params); err != nil {
		logrus.Errorf("writeStateDiffFor %s faild with err %s", blockHash.Hex(), err.Error())
	}
}

// rpcMarshalBlock uses the generalized output filler, then adds the total difficulty field
func (pea *PublicEthAPI) rpcMarshalBlock(b *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields, err := RPCMarshalBlock(b, inclTx, fullTx)
	if err != nil {
		return nil, err
	}
	if inclTx {
		td, err := pea.B.GetTd(b.Hash())
		if err != nil {
			return nil, err
		}
		fields["totalDifficulty"] = (*hexutil.Big)(td)
	}
	return fields, err
}

// rpcMarshalBlockWithUncleHashes uses the generalized output filler, then adds the total difficulty field
func (pea *PublicEthAPI) rpcMarshalBlockWithUncleHashes(b *types.Block, uncleHashes []common.Hash, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields, err := RPCMarshalBlockWithUncleHashes(b, uncleHashes, inclTx, fullTx)
	if err != nil {
		return nil, err
	}
	td, err := pea.B.GetTd(b.Hash())
	if err != nil {
		return nil, err
	}
	fields["totalDifficulty"] = (*hexutil.Big)(td)
	return fields, err
}

// toHexSlice creates a slice of hex-strings based on []byte.
func toHexSlice(b [][]byte) []string {
	r := make([]string, len(b))
	for i := range b {
		r[i] = hexutil.Encode(b[i])
	}
	return r
}

// decomposeLogs return logs from LogResult.
func decomposeLogs(logCIDs []LogResult) ([]*types.Log, error) {
	logs := make([]*types.Log, len(logCIDs))
	for i, l := range logCIDs {
		topics := make([]common.Hash, 0)
		if l.Topic0 != "" {
			topics = append(topics, common.HexToHash(l.Topic0))
		}
		if l.Topic1 != "" {
			topics = append(topics, common.HexToHash(l.Topic1))
		}
		if l.Topic2 != "" {
			topics = append(topics, common.HexToHash(l.Topic2))
		}
		if l.Topic3 != "" {
			topics = append(topics, common.HexToHash(l.Topic3))
		}

		// TODO: should we convert string to uint ?
		blockNum, err := strconv.ParseUint(l.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}

		logs[i] = &types.Log{
			Address:     common.HexToAddress(l.Address),
			Topics:      topics,
			Data:        l.Data,
			BlockNumber: blockNum,
			TxHash:      common.HexToHash(l.TxHash),
			TxIndex:     uint(l.TxnIndex),
			BlockHash:   common.HexToHash(l.BlockHash),
			Index:       uint(l.Index),
		}
	}

	return logs, nil
}
