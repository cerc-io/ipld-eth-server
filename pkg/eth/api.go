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
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"
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

// Call executes the given transaction on the state for the given block number.
//
// Additionally, the caller can specify a batch of contract for fields overriding.
//
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
func (pea *PublicEthAPI) Call(ctx context.Context, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *map[common.Address]account) (hexutil.Bytes, error) {
	var accounts map[common.Address]account
	if overrides != nil {
		accounts = *overrides
	}
	result, _, failed, err := DoCall(ctx, pea.B, args, blockNrOrHash, accounts, 5*time.Second, pea.B.Config.RPCGasCap)
	if failed && err == nil {
		return nil, errors.New("eth_call failed without error")
	}
	return (hexutil.Bytes)(result), err
}

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From     *common.Address `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Uint64 `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Data     *hexutil.Bytes  `json:"data"`
}

// account indicates the overriding fields of account during the execution of
// a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if statDiff is set, all diff will be applied first and then execute the call
// message.
type account struct {
	Nonce     *hexutil.Uint64              `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

func DoCall(ctx context.Context, b *Backend, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides map[common.Address]account, timeout time.Duration, globalGasCap *big.Int) ([]byte, uint64, bool, error) {
	defer func(start time.Time) {
		logrus.Debugf("Executing EVM call finished %s runtime %s", time.Now().String(), time.Since(start).String())
	}(time.Now())
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, 0, false, err
	}
	// Set sender address or use a default if none specified
	var addr common.Address
	if args.From == nil {
		if b.Config.DefaultSender != nil {
			addr = *b.Config.DefaultSender
		}
	} else {
		addr = *args.From
	}
	// Override the fields of specified contracts before execution.
	for addr, account := range overrides {
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
			return nil, 0, false, fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
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
	// Set default gas & gas price if none were set
	gas := uint64(math.MaxUint64 / 2)
	if args.Gas != nil {
		gas = uint64(*args.Gas)
	}
	if globalGasCap != nil && globalGasCap.Uint64() < gas {
		logrus.Warnf("Caller gas above allowance, capping; requested: %d, cap: %d", gas, globalGasCap)
		gas = globalGasCap.Uint64()
	}
	gasPrice := new(big.Int).SetUint64(params.GWei)
	if args.GasPrice != nil {
		gasPrice = args.GasPrice.ToInt()
	}

	value := new(big.Int)
	if args.Value != nil {
		value = args.Value.ToInt()
	}

	var data []byte
	if args.Data != nil {
		data = []byte(*args.Data)
	}

	// Create new call message
	msg := types.NewMessage(addr, args.To, 0, value, gas, gasPrice, data, false)

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
	evm, err := b.GetEVM(ctx, msg, state, header)
	if err != nil {
		return nil, 0, false, err
	}
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	res, gas, failed, err := core.ApplyMessage(evm, msg, gp)
	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, 0, false, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	return res, gas, failed, err
}
