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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	ipfsethdb "github.com/vulcanize/pg-ipfs-ethdb"

	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var (
	errPendingBlockNumber  = errors.New("pending block number not supported")
	errNegativeBlockNumber = errors.New("negative block number not supported")
)

const (
	RetrieveCanonicalBlockHashByNumber = `SELECT block_hash FROM eth.header_cids
									INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
									WHERE id = (SELECT canonical_header($1))`
	RetrieveCanonicalHeaderByNumber = `SELECT cid, data FROM eth.header_cids
									INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
									WHERE id = (SELECT canonical_header($1))`
	RetrieveTD = `SELECT td FROM eth.header_cids
			WHERE header_cids.block_hash = $1`
	RetrieveRPCTransaction = `SELECT blocks.data, block_hash, block_number, index FROM public.blocks, eth.transaction_cids, eth.header_cids
			WHERE blocks.key = transaction_cids.mh_key
			AND transaction_cids.header_id = header_cids.id
			AND transaction_cids.tx_hash = $1`
)

type Backend struct {
	// underlying postgres db
	DB *postgres.DB

	// postgres db interfaces
	Retriever     *CIDRetriever
	Fetcher       *IPLDFetcher
	IPLDRetriever *IPLDRetriever

	// ethereum interfaces
	EthDB         ethdb.Database
	StateDatabase state.Database

	Config *Config
}

type Config struct {
	ChainConfig   *params.ChainConfig
	VmConfig      vm.Config
	DefaultSender *common.Address
	RPCGasCap     *big.Int
}

func NewEthBackend(db *postgres.DB, c *Config) (*Backend, error) {
	r := NewCIDRetriever(db)
	ethDB := ipfsethdb.NewDatabase(db.DB)
	return &Backend{
		DB:            db,
		Retriever:     r,
		Fetcher:       NewIPLDFetcher(db),
		IPLDRetriever: NewIPLDRetriever(db),
		EthDB:         ethDB,
		StateDatabase: state.NewDatabase(ethDB),
		Config:        c,
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
	_, headerRLP, err := b.IPLDRetriever.RetrieveHeaderByHash(hash)
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
		if blockNrOrHash.RequireCanonical && b.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
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

// CurrentBlock returns the current block
func (b *Backend) CurrentBlock() *types.Block {
	block, _ := b.BlockByNumber(context.Background(), rpc.LatestBlockNumber)
	return block
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
		if blockNrOrHash.RequireCanonical && b.GetCanonicalHash(header.Number.Uint64()) != hash {
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

// BlockByNumber returns the requested canonical block.
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
	canonicalHash := b.GetCanonicalHash(uint64(number))
	if err != nil {
		return nil, err
	}
	// Retrieve all the CIDs for the block
	// TODO: optimize this by retrieving iplds directly rather than the cids first (this is remanent from when we fetched iplds through ipfs blockservice interface)
	headerCID, uncleCIDs, txCIDs, rctCIDs, err := b.Retriever.RetrieveBlockByHash(canonicalHash)
	if err != nil {
		return nil, err
	}

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

	// Fetch and decode the header IPLD
	headerIPLD, err := b.Fetcher.FetchHeader(tx, headerCID)
	if err != nil {
		return nil, err
	}
	var header types.Header
	if err := rlp.DecodeBytes(headerIPLD.Data, &header); err != nil {
		return nil, err
	}
	// Fetch and decode the uncle IPLDs
	uncleIPLDs, err := b.Fetcher.FetchUncles(tx, uncleCIDs)
	if err != nil {
		return nil, err
	}
	var uncles []*types.Header
	for _, uncleIPLD := range uncleIPLDs {
		var uncle types.Header
		if err := rlp.DecodeBytes(uncleIPLD.Data, &uncle); err != nil {
			return nil, err
		}
		uncles = append(uncles, &uncle)
	}
	// Fetch and decode the transaction IPLDs
	txIPLDs, err := b.Fetcher.FetchTrxs(tx, txCIDs)
	if err != nil {
		return nil, err
	}
	var transactions []*types.Transaction
	for _, txIPLD := range txIPLDs {
		var transaction types.Transaction
		if err := rlp.DecodeBytes(txIPLD.Data, &transaction); err != nil {
			return nil, err
		}
		transactions = append(transactions, &transaction)
	}
	// Fetch and decode the receipt IPLDs
	rctIPLDs, err := b.Fetcher.FetchRcts(tx, rctCIDs)
	if err != nil {
		return nil, err
	}
	var receipts []*types.Receipt
	for _, rctIPLD := range rctIPLDs {
		var receipt types.Receipt
		if err := rlp.DecodeBytes(rctIPLD.Data, &receipt); err != nil {
			return nil, err
		}
		receipts = append(receipts, &receipt)
	}
	// Compose everything together into a complete block
	return types.NewBlock(&header, transactions, uncles, receipts), err
}

// BlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (b *Backend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	// Retrieve all the CIDs for the block
	headerCID, uncleCIDs, txCIDs, rctCIDs, err := b.Retriever.RetrieveBlockByHash(hash)
	if err != nil {
		return nil, err
	}

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

	// Fetch and decode the header IPLD
	headerIPLD, err := b.Fetcher.FetchHeader(tx, headerCID)
	if err != nil {
		return nil, err
	}
	var header types.Header
	if err := rlp.DecodeBytes(headerIPLD.Data, &header); err != nil {
		return nil, err
	}
	// Fetch and decode the uncle IPLDs
	uncleIPLDs, err := b.Fetcher.FetchUncles(tx, uncleCIDs)
	if err != nil {
		return nil, err
	}
	var uncles []*types.Header
	for _, uncleIPLD := range uncleIPLDs {
		var uncle types.Header
		if err := rlp.DecodeBytes(uncleIPLD.Data, &uncle); err != nil {
			return nil, err
		}
		uncles = append(uncles, &uncle)
	}
	// Fetch and decode the transaction IPLDs
	txIPLDs, err := b.Fetcher.FetchTrxs(tx, txCIDs)
	if err != nil {
		return nil, err
	}
	var transactions []*types.Transaction
	for _, txIPLD := range txIPLDs {
		var transaction types.Transaction
		if err := rlp.DecodeBytes(txIPLD.Data, &transaction); err != nil {
			return nil, err
		}
		transactions = append(transactions, &transaction)
	}
	// Fetch and decode the receipt IPLDs
	rctIPLDs, err := b.Fetcher.FetchRcts(tx, rctCIDs)
	if err != nil {
		return nil, err
	}
	var receipts []*types.Receipt
	for _, rctIPLD := range rctIPLDs {
		var receipt types.Receipt
		if err := rlp.DecodeBytes(rctIPLD.Data, &receipt); err != nil {
			return nil, err
		}
		receipts = append(receipts, &receipt)
	}
	// Compose everything together into a complete block
	return types.NewBlock(&header, transactions, uncles, receipts), err
}

// GetTransaction retrieves a tx by hash
// It also returns the blockhash, blocknumber, and tx index associated with the transaction
func (b *Backend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	var tempTxStruct struct {
		Data        []byte `db:"data"`
		BlockHash   string `db:"block_hash"`
		BlockNumber uint64 `db:"block_number"`
		Index       uint64 `db:"index"`
	}
	if err := b.DB.Get(&tempTxStruct, RetrieveRPCTransaction, txHash.String()); err != nil {
		return nil, common.Hash{}, 0, 0, err
	}
	var transaction types.Transaction
	if err := rlp.DecodeBytes(tempTxStruct.Data, &transaction); err != nil {
		return nil, common.Hash{}, 0, 0, err
	}
	return &transaction, common.HexToHash(tempTxStruct.BlockHash), tempTxStruct.BlockNumber, tempTxStruct.Index, nil
}

// GetReceipts retrieves receipts for provided block hash
func (b *Backend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	_, receiptBytes, err := b.IPLDRetriever.RetrieveReceiptsByBlockHash(hash)
	if err != nil {
		return nil, err
	}
	rcts := make(types.Receipts, 0, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		rct := new(types.Receipt)
		if err := rlp.DecodeBytes(rctBytes, rct); err != nil {
			return nil, err
		}
		rcts[i] = rct
	}
	return rcts, nil
}

// GetLogs returns all the logs for the given block hash
func (b *Backend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	_, receiptBytes, err := b.IPLDRetriever.RetrieveReceiptsByBlockHash(hash)
	if err != nil {
		return nil, err
	}
	logs := make([][]*types.Log, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		var rct types.Receipt
		if err := rlp.DecodeBytes(rctBytes, &rct); err != nil {
			return nil, err
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
		if blockNrOrHash.RequireCanonical && b.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := state.New(header.Root, b.StateDatabase)
		return stateDb, header, err
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
	stateDb, err := state.New(header.Root, b.StateDatabase)
	return stateDb, header, err
}

// GetCanonicalHash gets the canonical hash for the provided number, if there is one
func (b *Backend) GetCanonicalHash(number uint64) common.Hash {
	var hashResult string
	if err := b.DB.Get(&hashResult, RetrieveCanonicalBlockHashByNumber, number); err != nil {
		return common.Hash{}
	}
	return common.HexToHash(hashResult)
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
func (b *Backend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	c := core.NewEVMContext(msg, header, b, nil)
	return vm.NewEVM(c, state, b.Config.ChainConfig, b.Config.VmConfig), nil
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

// RPCGasCap returns the configured gas cap for the rpc server
func (b *Backend) RPCGasCap() *big.Int {
	return b.Config.RPCGasCap
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
