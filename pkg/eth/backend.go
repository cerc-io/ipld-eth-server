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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	validator "github.com/cerc-io/eth-ipfs-state-validator/v4/pkg"
	ipfsethdb "github.com/cerc-io/ipfs-ethdb/v4/postgres"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/shared"
	ipld_eth_statedb "github.com/cerc-io/ipld-eth-statedb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	ethServerShared "github.com/ethereum/go-ethereum/statediff/indexer/shared"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/jmoiron/sqlx"
)

var (
	errPendingBlockNumber     = errors.New("pending block number not supported")
	errNegativeBlockNumber    = errors.New("negative block number not supported")
	errHeaderHashNotFound     = errors.New("header for hash not found")
	errHeaderNotFound         = errors.New("header not found")
	errMultipleHeadersForHash = errors.New("more than one headers for the given hash")
	errTxHashNotFound         = errors.New("transaction for hash not found")
	errTxHashInMultipleBlocks = errors.New("transaction for hash found in more than one canonical block")
)

const (
	StateDBGroupCacheName = "statedb"
)

type Backend struct {
	// underlying postgres db
	DB *sqlx.DB

	// postgres db interfaces
	Retriever *Retriever

	// ethereum interfaces
	EthDB         ethdb.Database
	StateDatabase state.Database
	// We'll use this state.Database for eth_call and any place we don't need trie access
	IpldStateDatabase ipld_eth_statedb.StateDatabase

	Config *Config
}

type Config struct {
	ChainConfig      *params.ChainConfig
	VMConfig         vm.Config
	DefaultSender    *common.Address
	RPCGasCap        *big.Int
	GroupCacheConfig *shared.GroupCacheConfig
}

func NewEthBackend(db *sqlx.DB, c *Config) (*Backend, error) {
	gcc := c.GroupCacheConfig

	groupName := gcc.StateDB.Name
	if groupName == "" {
		groupName = StateDBGroupCacheName
	}

	r := NewRetriever(db)
	ethDB := ipfsethdb.NewDatabase(db, ipfsethdb.CacheConfig{
		Name:           groupName,
		Size:           gcc.StateDB.CacheSizeInMB * 1024 * 1024,
		ExpiryDuration: time.Minute * time.Duration(gcc.StateDB.CacheExpiryInMins),
	})

	logStateDBStatsOnTimer(ethDB.(*ipfsethdb.Database), gcc)
	ipldStateDB, err := ipld_eth_statedb.NewStateDatabaseWithSqlxPool(db)
	if err != nil {
		return nil, err
	}
	return &Backend{
		DB:                db,
		Retriever:         r,
		EthDB:             ethDB,
		StateDatabase:     state.NewDatabase(ethDB),
		IpldStateDatabase: ipldStateDB,
		Config:            c,
	}, nil
}

// ChainDb returns the backend's underlying chain database
func (b *Backend) ChainDb() ethdb.Database {
	return b.EthDB
}

// HeaderByNumber gets the canonical header for the provided block number
func (b *Backend) HeaderByNumber(ctx context.Context, blockNumber rpc.BlockNumber) (*types.Header, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	if number < 0 {
		return nil, errNegativeBlockNumber
	}
	_, canonicalHeaderRLP, err := b.GetCanonicalHeader(uint64(number))
	if err != nil {
		return nil, err
	}

	header := new(types.Header)
	return header, rlp.DecodeBytes(canonicalHeaderRLP, header)
}

// HeaderByHash gets the header for the provided block hash
func (b *Backend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	// Begin tx
	tx, err := b.DB.Beginx()
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

	_, headerRLP, err := b.Retriever.RetrieveHeaderByHash(tx, hash)
	if err != nil {
		return nil, err
	}
	header := new(types.Header)
	return header, rlp.DecodeBytes(headerRLP, header)
}

// HeaderByNumberOrHash gets the header for the provided block hash or number
func (b *Backend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *Backend) PendingBlockAndReceipts() (*types.Block, types.Receipts) {
	return nil, nil
}

// GetTd gets the total difficulty at the given block hash
func (b *Backend) GetTd(blockHash common.Hash) (*big.Int, error) {
	var tdStr string
	err := b.DB.Get(&tdStr, RetrieveTD, blockHash.String())
	if err != nil {
		return nil, err
	}
	td, ok := new(big.Int).SetString(tdStr, 10)
	if !ok {
		return nil, errors.New("total difficulty retrieved from Postgres cannot be converted to an integer")
	}
	return td, nil
}

// ChainConfig returns the active chain configuration.
func (b *Backend) ChainConfig() *params.ChainConfig {
	return b.Config.ChainConfig
}

// CurrentBlock returns the current block
func (b *Backend) CurrentBlock() (*types.Block, error) {
	block, err := b.BlockByNumber(context.Background(), rpc.LatestBlockNumber)
	return block, err
}

// BlockByNumberOrHash returns block by number or hash
func (b *Backend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block, err := b.BlockByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// BlockByNumber returns the requested canonical block
func (b *Backend) BlockByNumber(ctx context.Context, blockNumber rpc.BlockNumber) (*types.Block, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	if number < 0 {
		return nil, errNegativeBlockNumber
	}

	// Get the canonical hash
	canonicalHash, err := b.GetCanonicalHash(uint64(number))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return b.BlockByHash(ctx, canonicalHash)
}

// BlockByHash returns the requested block
func (b *Backend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	// Begin tx
	tx, err := b.DB.Beginx()
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

	// Fetch header
	header, err := b.GetHeaderByBlockHash(tx, hash)
	if err != nil {
		log.Error("error fetching header: ", err)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	blockNumber := header.Number.Uint64()

	// Fetch uncles
	uncles, err := b.GetUnclesByBlockHashAndNumber(tx, hash, blockNumber)
	if err != nil && err != sql.ErrNoRows {
		log.Error("error fetching uncles: ", err)
		return nil, err
	}

	// We should not have any non-determinism in the ordering of the uncles returned to us now
	uncleHash := types.CalcUncleHash(uncles)
	// Check if uncle hash matches expected hash
	if uncleHash != header.UncleHash {
		log.Error("uncle hash mismatch for block hash: ", hash.Hex())
	}

	// Fetch transactions
	transactions, err := b.GetTransactionsByBlockHashAndNumber(tx, hash, blockNumber)
	if err != nil && err != sql.ErrNoRows {
		log.Error("error fetching transactions: ", err)
		return nil, err
	}

	// Fetch receipts
	receipts, err := b.GetReceiptsByBlockHashAndNumber(tx, hash, blockNumber)
	if err != nil && err != sql.ErrNoRows {
		log.Error("error fetching receipts: ", err)
		return nil, err
	}

	// Compose everything together into a complete block
	return types.NewBlock(header, transactions, uncles, receipts, new(trie.Trie)), err
}

// GetHeaderByBlockHash retrieves header for a provided block hash
func (b *Backend) GetHeaderByBlockHash(tx *sqlx.Tx, hash common.Hash) (*types.Header, error) {
	_, headerRLP, err := b.Retriever.RetrieveHeaderByHash(tx, hash)
	if err != nil {
		return nil, err
	}

	header := new(types.Header)
	return header, rlp.DecodeBytes(headerRLP, header)
}

// GetUnclesByBlockHash retrieves uncles for a provided block hash
func (b *Backend) GetUnclesByBlockHash(tx *sqlx.Tx, hash common.Hash) ([]*types.Header, error) {
	_, uncleBytes, err := b.Retriever.RetrieveUnclesByBlockHash(tx, hash)
	if err != nil {
		return nil, err
	}

	uncles := make([]*types.Header, 0)
	if err := rlp.DecodeBytes(uncleBytes, uncles); err != nil {
		return nil, err
	}

	return uncles, nil
}

// GetUnclesByBlockHashAndNumber retrieves uncles for a provided block hash and number
func (b *Backend) GetUnclesByBlockHashAndNumber(tx *sqlx.Tx, hash common.Hash, number uint64) ([]*types.Header, error) {
	_, uncleBytes, err := b.Retriever.RetrieveUncles(tx, hash, number)
	if err != nil {
		return nil, err
	}

	uncles := make([]*types.Header, 0)
	if err := rlp.DecodeBytes(uncleBytes, uncles); err != nil {
		return nil, err
	}

	return uncles, nil
}

// GetTransactionsByBlockHash retrieves transactions for a provided block hash
func (b *Backend) GetTransactionsByBlockHash(tx *sqlx.Tx, hash common.Hash) (types.Transactions, error) {
	_, transactionBytes, err := b.Retriever.RetrieveTransactionsByBlockHash(tx, hash)
	if err != nil {
		return nil, err
	}

	txs := make(types.Transactions, len(transactionBytes))
	for i, txBytes := range transactionBytes {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(txBytes); err != nil {
			return nil, err
		}

		txs[i] = &tx
	}

	return txs, nil
}

// GetTransactionsByBlockHashAndNumber retrieves transactions for a provided block hash and number
func (b *Backend) GetTransactionsByBlockHashAndNumber(tx *sqlx.Tx, hash common.Hash, number uint64) (types.Transactions, error) {
	_, transactionBytes, err := b.Retriever.RetrieveTransactions(tx, hash, number)
	if err != nil {
		return nil, err
	}

	txs := make(types.Transactions, len(transactionBytes))
	for i, txBytes := range transactionBytes {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(txBytes); err != nil {
			return nil, err
		}

		txs[i] = &tx
	}

	return txs, nil
}

// GetReceiptsByBlockHash retrieves receipts for a provided block hash
func (b *Backend) GetReceiptsByBlockHash(tx *sqlx.Tx, hash common.Hash) (types.Receipts, error) {
	_, receiptBytes, txs, err := b.Retriever.RetrieveReceiptsByBlockHash(tx, hash)
	if err != nil {
		return nil, err
	}
	rcts := make(types.Receipts, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		rct := new(types.Receipt)
		if err := rct.UnmarshalBinary(rctBytes); err != nil {
			return nil, err
		}
		rct.TxHash = txs[i]
		rcts[i] = rct
	}
	return rcts, nil
}

// GetReceiptsByBlockHashAndNumber retrieves receipts for a provided block hash and number
func (b *Backend) GetReceiptsByBlockHashAndNumber(tx *sqlx.Tx, hash common.Hash, number uint64) (types.Receipts, error) {
	_, receiptBytes, txs, err := b.Retriever.RetrieveReceipts(tx, hash, number)
	if err != nil {
		return nil, err
	}
	rcts := make(types.Receipts, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		rct := new(types.Receipt)
		if err := rct.UnmarshalBinary(rctBytes); err != nil {
			return nil, err
		}
		rct.TxHash = txs[i]
		rcts[i] = rct
	}
	return rcts, nil
}

// GetTransaction retrieves a tx by hash
// It also returns the blockhash, blocknumber, and tx index associated with the transaction
func (b *Backend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	type txRes struct {
		Data        []byte `db:"data"`
		HeaderID    string `db:"header_id"`
		BlockNumber uint64 `db:"block_number"`
		Index       uint64 `db:"index"`
	}
	var res = make([]txRes, 0)
	if err := b.DB.Select(&res, RetrieveRPCTransaction, txHash.String()); err != nil {
		return nil, common.Hash{}, 0, 0, err
	}

	if len(res) == 0 {
		return nil, common.Hash{}, 0, 0, errTxHashNotFound
	} else if len(res) > 1 {
		// a transaction can be part of a only one canonical block
		return nil, common.Hash{}, 0, 0, errTxHashInMultipleBlocks
	}

	var transaction types.Transaction
	if err := transaction.UnmarshalBinary(res[0].Data); err != nil {
		return nil, common.Hash{}, 0, 0, err
	}

	return &transaction, common.HexToHash(res[0].HeaderID), res[0].BlockNumber, res[0].Index, nil
}

// GetReceipts retrieves receipts for provided block hash
func (b *Backend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	// Begin tx
	tx, err := b.DB.Beginx()
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

	blockNumber, err := b.Retriever.RetrieveBlockNumberByHash(tx, hash)
	if err != nil {
		return nil, err
	}

	return b.GetReceiptsByBlockHashAndNumber(tx, hash, blockNumber)
}

// GetLogs returns all the logs for the given block hash
func (b *Backend) GetLogs(ctx context.Context, hash common.Hash, number uint64) ([][]*types.Log, error) {
	// Begin tx
	tx, err := b.DB.Beginx()
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

	_, receiptBytes, txs, err := b.Retriever.RetrieveReceipts(tx, hash, number)
	if err != nil {
		return nil, err
	}
	logs := make([][]*types.Log, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		var rct types.Receipt
		if err := rlp.DecodeBytes(rctBytes, &rct); err != nil {
			return nil, err
		}

		for _, log := range rct.Logs {
			log.TxHash = txs[i]
		}

		logs[i] = rct.Logs
	}
	return logs, nil
}

// StateAndHeaderByNumberOrHash returns the statedb and header for the provided block number or hash
func (b *Backend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := state.New(header.Root, b.StateDatabase, nil)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

// IPLDStateDBAndHeaderByNumberOrHash returns the statedb and header for the provided block number or hash
func (b *Backend) IPLDStateDBAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*ipld_eth_statedb.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.IPLDStateDBAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDB, err := ipld_eth_statedb.New(header.Root, b.IpldStateDatabase)
		return stateDB, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

// StateAndHeaderByNumber returns the statedb and header for a provided block number
func (b *Backend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if number == rpc.PendingBlockNumber {
		return nil, nil, errPendingBlockNumber
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := state.New(header.Root, b.StateDatabase, nil)
	return stateDb, header, err
}

// IPLDStateDBAndHeaderByNumber returns the statedb and header for a provided block number
func (b *Backend) IPLDStateDBAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*ipld_eth_statedb.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if number == rpc.PendingBlockNumber {
		return nil, nil, errPendingBlockNumber
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := ipld_eth_statedb.New(header.Root, b.IpldStateDatabase)
	return stateDb, header, err
}

// GetCanonicalHash gets the canonical hash for the provided number, if there is one
func (b *Backend) GetCanonicalHash(number uint64) (common.Hash, error) {
	var hashResult string
	if err := b.DB.Get(&hashResult, RetrieveCanonicalBlockHashByNumber, number); err != nil {
		return common.Hash{}, err
	}
	return common.HexToHash(hashResult), nil
}

type rowResult struct {
	CID  string
	Data []byte
}

// GetCanonicalHeader gets the canonical header for the provided number, if there is one
func (b *Backend) GetCanonicalHeader(number uint64) (string, []byte, error) {
	headerResult := new(rowResult)
	return headerResult.CID, headerResult.Data, b.DB.QueryRowx(RetrieveCanonicalHeaderByNumber, number).StructScan(headerResult)
}

// GetEVM constructs and returns a vm.EVM
func (b *Backend) GetEVM(ctx context.Context, msg core.Message, state vm.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	vmError := func() error { return nil }
	txContext := core.NewEVMTxContext(msg)
	blockContext := core.NewEVMBlockContext(header, b, nil)
	return vm.NewEVM(blockContext, txContext, state, b.Config.ChainConfig, b.Config.VMConfig), vmError, nil
}

// GetAccountByNumberOrHash returns the account object for the provided address at the block corresponding to the provided number or hash
func (b *Backend) GetAccountByNumberOrHash(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*types.StateAccount, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.GetAccountByNumber(ctx, address, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		return b.GetAccountByHash(ctx, address, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetAccountByNumber returns the account object for the provided address at the canonical block at the provided height
func (b *Backend) GetAccountByNumber(ctx context.Context, address common.Address, blockNumber rpc.BlockNumber) (*types.StateAccount, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	hash, err := b.GetCanonicalHash(uint64(number))
	if err == sql.ErrNoRows {
		return nil, errHeaderNotFound
	} else if err != nil {
		return nil, err
	}

	return b.GetAccountByHash(ctx, address, hash)
}

// GetAccountByHash returns the account object for the provided address at the block with the provided hash
func (b *Backend) GetAccountByHash(ctx context.Context, address common.Address, hash common.Hash) (*types.StateAccount, error) {
	_, err := b.HeaderByHash(context.Background(), hash)
	if err == sql.ErrNoRows {
		return nil, errHeaderHashNotFound
	} else if err != nil {
		return nil, err
	}

	_, accountRlp, err := b.Retriever.RetrieveAccountByAddressAndBlockHash(address, hash)
	if err != nil {
		return nil, err
	}

	acct := new(types.StateAccount)
	return acct, rlp.DecodeBytes(accountRlp, acct)
}

// GetCodeByNumberOrHash returns the byte code for the contract deployed at the provided address at the block with the provided hash or block number
func (b *Backend) GetCodeByNumberOrHash(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) ([]byte, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.GetCodeByNumber(ctx, address, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		return b.GetCodeByHash(ctx, address, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetCodeByNumber returns the byte code for the contract deployed at the provided address at the canonical block with the provided block number
func (b *Backend) GetCodeByNumber(ctx context.Context, address common.Address, blockNumber rpc.BlockNumber) ([]byte, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	hash, err := b.GetCanonicalHash(uint64(number))
	if err != nil {
		return nil, err
	}
	if hash == (common.Hash{}) {
		return nil, fmt.Errorf("no canoncial block hash found for provided height (%d)", number)
	}
	return b.GetCodeByHash(ctx, address, hash)
}

// GetCodeByHash returns the byte code for the contract deployed at the provided address at the block with the provided hash
func (b *Backend) GetCodeByHash(ctx context.Context, address common.Address, hash common.Hash) ([]byte, error) {
	codeHash := make([]byte, 0)
	leafKey := crypto.Keccak256Hash(address.Bytes())
	// Begin tx
	tx, err := b.DB.Beginx()
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
	err = tx.Get(&codeHash, RetrieveCodeHashByLeafKeyAndBlockHash, leafKey.Hex(), hash.Hex())
	if err != nil {
		return nil, err
	}
	var mhKey string
	mhKey, err = ethServerShared.MultihashKeyFromKeccak256(common.BytesToHash(codeHash))
	if err != nil {
		return nil, err
	}
	code := make([]byte, 0)
	err = tx.Get(&code, RetrieveCodeByMhKey, mhKey)
	return code, err
}

// GetStorageByNumberOrHash returns the storage value for the provided contract address an storage key at the block corresponding to the provided number or hash
func (b *Backend) GetStorageByNumberOrHash(ctx context.Context, address common.Address, key common.Hash, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.GetStorageByNumber(ctx, address, key, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		return b.GetStorageByHash(ctx, address, key, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetStorageByNumber returns the storage value for the provided contract address an storage key at the block corresponding to the provided number
func (b *Backend) GetStorageByNumber(ctx context.Context, address common.Address, key common.Hash, blockNumber rpc.BlockNumber) (hexutil.Bytes, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	hash, err := b.GetCanonicalHash(uint64(number))
	if err == sql.ErrNoRows {
		return nil, errHeaderNotFound
	} else if err != nil {
		return nil, err
	}

	return b.GetStorageByHash(ctx, address, key, hash)
}

// GetStorageByHash returns the storage value for the provided contract address an storage key at the block corresponding to the provided hash
func (b *Backend) GetStorageByHash(ctx context.Context, address common.Address, key, hash common.Hash) (hexutil.Bytes, error) {
	_, err := b.HeaderByHash(context.Background(), hash)
	if err == sql.ErrNoRows {
		return nil, errHeaderHashNotFound
	} else if err != nil {
		return nil, err
	}

	_, _, storageRlp, err := b.Retriever.RetrieveStorageAtByAddressAndStorageSlotAndBlockHash(address, key, hash)
	return storageRlp, err
}

func (b *Backend) GetSlice(path string, depth int, root common.Hash, storage bool) (*GetSliceResponse, error) {
	response := new(GetSliceResponse)
	response.init(path, depth, root)

	// Metadata fields
	metaData := metaDataFields{}

	startTime := makeTimestamp()
	t, _ := b.StateDatabase.OpenTrie(root)
	metaData.trieLoadingTime = makeTimestamp() - startTime

	// Convert the head hex path to a decoded byte path
	headPath := common.FromHex(path)

	// Get Stem nodes
	err := b.getSliceStem(headPath, t, response, &metaData, storage)
	if err != nil {
		return nil, err
	}

	// Get Head node
	err = b.getSliceHead(headPath, t, response, &metaData, storage)
	if err != nil {
		return nil, err
	}

	if depth > 0 {
		// Get Slice nodes
		err = b.getSliceTrie(headPath, t, response, &metaData, depth, storage)
		if err != nil {
			return nil, err
		}
	}

	response.populateMetaData(metaData)

	return response, nil
}

func (b *Backend) getSliceStem(headPath []byte, t state.Trie, response *GetSliceResponse, metaData *metaDataFields, storage bool) error {
	leavesFetchTime := int64(0)
	totalStemStartTime := makeTimestamp()

	for i := 0; i < len(headPath); i++ {
		// Create path for each node along the stem
		nodePath := make([]byte, len(headPath[:i]))
		copy(nodePath, headPath[:i])

		rawNode, _, err := t.(*trie.StateTrie).TryGetNode(trie.HexToCompact(nodePath))
		if err != nil {
			return err
		}

		// Skip if node not found
		if rawNode == nil {
			continue
		}

		node, nodeElements, err := ResolveNode(nodePath, rawNode, b.StateDatabase.TrieDB())
		if err != nil {
			return err
		}

		leafFetchTime, err := fillSliceNodeData(b.EthDB, response.TrieNodes.Stem, response.Leaves, node, nodeElements, storage)
		if err != nil {
			return err
		}

		// Update metadata
		depthReached := len(node.Path) - len(headPath)
		if depthReached > metaData.maxDepth {
			metaData.maxDepth = depthReached
		}
		if node.NodeType == Leaf {
			metaData.leafCount++
		}
		leavesFetchTime += leafFetchTime
	}

	// Update metadata time metrics
	totalStemTime := makeTimestamp() - totalStemStartTime
	metaData.sliceNodesFetchTime = totalStemTime - leavesFetchTime
	metaData.leavesFetchTime += leavesFetchTime

	return nil
}

func (b *Backend) getSliceHead(headPath []byte, t state.Trie, response *GetSliceResponse, metaData *metaDataFields, storage bool) error {
	totalHeadStartTime := makeTimestamp()

	rawNode, _, err := t.(*trie.StateTrie).TryGetNode(trie.HexToCompact(headPath))
	if err != nil {
		return err
	}

	// Skip if node not found
	if rawNode == nil {
		return nil
	}

	node, nodeElements, err := ResolveNode(headPath, rawNode, b.StateDatabase.TrieDB())
	if err != nil {
		return err
	}

	leafFetchTime, err := fillSliceNodeData(b.EthDB, response.TrieNodes.Head, response.Leaves, node, nodeElements, storage)
	if err != nil {
		return err
	}

	// Update metadata
	depthReached := len(node.Path) - len(headPath)
	if depthReached > metaData.maxDepth {
		metaData.maxDepth = depthReached
	}
	if node.NodeType == Leaf {
		metaData.leafCount++
	}

	// Update metadata time metrics
	totalHeadTime := makeTimestamp() - totalHeadStartTime
	metaData.stemNodesFetchTime = totalHeadTime - leafFetchTime
	metaData.leavesFetchTime += leafFetchTime

	return nil
}

func (b *Backend) getSliceTrie(headPath []byte, t state.Trie, response *GetSliceResponse, metaData *metaDataFields, depth int, storage bool) error {
	it, timeTaken := getIteratorAtPath(t, headPath)
	metaData.trieLoadingTime += timeTaken

	leavesFetchTime := int64(0)
	totalSliceStartTime := makeTimestamp()

	headPathLen := len(headPath)
	maxPathLen := headPathLen + depth
	descend := true
	for it.Next(descend) {
		pathLen := len(it.Path())

		// End iteration on coming out of subtrie
		if pathLen <= headPathLen {
			break
		}

		// Avoid descending further if max depth reached
		if pathLen >= maxPathLen {
			descend = false
		} else {
			descend = true
		}

		// Skip value nodes
		if it.Leaf() || bytes.Equal(nullHashBytes, it.Hash().Bytes()) {
			continue
		}

		node, nodeElements, err := ResolveNodeIt(it, b.StateDatabase.TrieDB())
		if err != nil {
			return err
		}

		leafFetchTime, err := fillSliceNodeData(b.EthDB, response.TrieNodes.Slice, response.Leaves, node, nodeElements, storage)
		if err != nil {
			return err
		}

		// Update metadata
		depthReached := len(node.Path) - len(headPath)
		if depthReached > metaData.maxDepth {
			metaData.maxDepth = depthReached
		}
		if node.NodeType == Leaf {
			metaData.leafCount++
		}
		leavesFetchTime += leafFetchTime
	}

	// Update metadata time metrics
	totalSliceTime := makeTimestamp() - totalSliceStartTime
	metaData.sliceNodesFetchTime = totalSliceTime - leavesFetchTime
	metaData.leavesFetchTime += leavesFetchTime

	return nil
}

// Engine satisfied the ChainContext interface
func (b *Backend) Engine() consensus.Engine {
	// TODO: we need to support more than just ethash based engines
	return ethash.NewFaker()
}

// GetHeader satisfied the ChainContext interface
func (b *Backend) GetHeader(hash common.Hash, height uint64) *types.Header {
	header, err := b.HeaderByHash(context.Background(), hash)
	if err != nil {
		return nil
	}
	return header
}

// ValidateTrie validates the trie for the given stateRoot
func (b *Backend) ValidateTrie(stateRoot common.Hash) error {
	return validator.NewValidator(nil, b.EthDB).ValidateTrie(stateRoot)
}

// RPCGasCap returns the configured gas cap for the rpc server
func (b *Backend) RPCGasCap() uint64 {
	return b.Config.RPCGasCap.Uint64()
}

func (b *Backend) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (b *Backend) BloomStatus() (uint64, uint64) {
	panic("implement me")
}

func (b *Backend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	panic("implement me")
}

func logStateDBStatsOnTimer(ethDB *ipfsethdb.Database, gcc *shared.GroupCacheConfig) {
	// No stats logging if interval isn't a positive integer.
	if gcc.StateDB.LogStatsIntervalInSecs <= 0 {
		return
	}

	ticker := time.NewTicker(time.Duration(gcc.StateDB.LogStatsIntervalInSecs) * time.Second)

	go func() {
		for range ticker.C {
			log.Infof("%s groupcache stats: %+v", StateDBGroupCacheName, ethDB.GetCacheStats())
		}
	}()
}
