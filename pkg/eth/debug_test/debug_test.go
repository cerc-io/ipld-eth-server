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

package eth_debug_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/shared"
)

var (
	db          *sqlx.DB
	chainConfig = &*params.TestChainConfig
	mockTD      = big.NewInt(1337)
	ctx         = context.Background()
	tb          *testBackend
	accounts    Accounts
	genBlocks   int
)

var _ = BeforeSuite(func() {
	// db and type initializations
	var err error
	db = shared.SetupDB()

	// Initialize test accounts
	accounts = newAccounts(3)
	genesis := &core.Genesis{
		Config: chainConfig,
		Alloc: core.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(params.Ether)},
			accounts[1].addr: {Balance: big.NewInt(params.Ether)},
			accounts[2].addr: {Balance: big.NewInt(params.Ether)},
		},
	}
	genBlocks = 10
	signer := types.HomesteadSigner{}
	tb, blocks, receipts := newTestBackend(genBlocks, genesis, func(i int, b *core.BlockGen) {
		// Transfer from account[0] to account[1]
		//    value: 1000 wei
		//    fee:   0 wei
		tx, _ := types.SignTx(types.NewTransaction(uint64(i), accounts[1].addr, big.NewInt(1000), params.TxGas, b.BaseFee(), nil), signer, accounts[0].key)
		b.AddTx(tx)
	})
	transformer := shared.SetupTestStateDiffIndexer(ctx, chainConfig, blocks[0].Hash())
	params := statediff.Params{}

	// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
	builder := statediff.NewBuilder(adapt.GethStateView(tb.chain.StateCache()))
	for i, block := range blocks {
		var args statediff.Args
		if i == 0 {
			args = statediff.Args{
				OldStateRoot: common.Hash{},
				NewStateRoot: block.Root(),
				BlockNumber:  block.Number(),
				BlockHash:    block.Hash(),
			}
		} else {
			args = statediff.Args{
				OldStateRoot: blocks[i-1].Root(),
				NewStateRoot: block.Root(),
				BlockNumber:  block.Number(),
				BlockHash:    block.Hash(),
			}
		}
		diff, err := builder.BuildStateDiffObject(args, params)
		Expect(err).ToNot(HaveOccurred())
		tx, err := transformer.PushBlock(block, receipts[i], mockTD)
		Expect(err).ToNot(HaveOccurred())
		defer tx.RollbackOnFailure(err)

		for _, node := range diff.Nodes {
			err = transformer.PushStateNode(tx, node, block.Hash().String())
			Expect(err).ToNot(HaveOccurred())
		}

		for _, ipld := range diff.IPLDs {
			err = transformer.PushIPLD(tx, ipld)
			Expect(err).ToNot(HaveOccurred())
		}

		err = tx.Submit()
		Expect(err).ToNot(HaveOccurred())
	}

	backend, err := eth.NewEthBackend(db, &eth.Config{
		ChainConfig: chainConfig,
		VMConfig:    vm.Config{},
		RPCGasCap:   big.NewInt(10000000000), // Max gas capacity for a rpc call.
		GroupCacheConfig: &shared.GroupCacheConfig{
			StateDB: shared.GroupConfig{
				Name:                   "eth_debug_test",
				CacheSizeInMB:          8,
				CacheExpiryInMins:      60,
				LogStatsIntervalInSecs: 0,
			},
		},
	})
	Expect(err).ToNot(HaveOccurred())

	tracingAPI, _ = eth.NewTracingAPI(backend, nil, eth.APIConfig{StateDiffTimeout: shared.DefaultStateDiffTimeout})
	tb.teardown()
})

var _ = AfterSuite(func() {
	shared.TearDownDB(db)
})

var (
	tracingAPI *eth.TracingAPI
)

var _ = Describe("eth state reading tests", func() {
	Describe("debug_traceCall", func() {
		It("Works", func() {
			var testSuite = []struct {
				blockNumber rpc.BlockNumber
				call        eth.TransactionArgs
				config      *eth.TraceCallConfig
				expectErr   error
				expect      string
			}{
				// Standard JSON trace upon the genesis, plain transfer.
				{
					blockNumber: rpc.BlockNumber(0),
					call: eth.TransactionArgs{
						From:  &accounts[0].addr,
						To:    &accounts[1].addr,
						Value: (*hexutil.Big)(big.NewInt(1000)),
					},
					config:    nil,
					expectErr: nil,
					expect:    `{"gas":21000,"failed":false,"returnValue":"","structLogs":[]}`,
				},
				// Standard JSON trace upon the head, plain transfer.
				{
					blockNumber: rpc.BlockNumber(genBlocks),
					call: eth.TransactionArgs{
						From:  &accounts[0].addr,
						To:    &accounts[1].addr,
						Value: (*hexutil.Big)(big.NewInt(1000)),
					},
					config:    nil,
					expectErr: nil,
					expect:    `{"gas":21000,"failed":false,"returnValue":"","structLogs":[]}`,
				},
				// Standard JSON trace upon the non-existent block, error expects
				{
					blockNumber: rpc.BlockNumber(genBlocks + 1),
					call: eth.TransactionArgs{
						From:  &accounts[0].addr,
						To:    &accounts[1].addr,
						Value: (*hexutil.Big)(big.NewInt(1000)),
					},
					config:    nil,
					expectErr: fmt.Errorf("block #%d not found", genBlocks+1),
					//expect:    nil,
				},
				// Standard JSON trace upon the latest block
				{
					blockNumber: rpc.LatestBlockNumber,
					call: eth.TransactionArgs{
						From:  &accounts[0].addr,
						To:    &accounts[1].addr,
						Value: (*hexutil.Big)(big.NewInt(1000)),
					},
					config:    nil,
					expectErr: nil,
					expect:    `{"gas":21000,"failed":false,"returnValue":"","structLogs":[]}`,
				},
				// Tracing on 'pending' should fail:
				{
					blockNumber: rpc.PendingBlockNumber,
					call: eth.TransactionArgs{
						From:  &accounts[0].addr,
						To:    &accounts[1].addr,
						Value: (*hexutil.Big)(big.NewInt(1000)),
					},
					config:    nil,
					expectErr: fmt.Errorf("tracing on top of pending is not supported"),
				},
				{
					blockNumber: rpc.LatestBlockNumber,
					call: eth.TransactionArgs{
						From:  &accounts[0].addr,
						Input: &hexutil.Bytes{0x43}, // blocknumber
					},
					config: &eth.TraceCallConfig{
						BlockOverrides: &eth.BlockOverrides{Number: (*hexutil.Big)(big.NewInt(0x1337))},
					},
					expectErr: nil,
					expect: ` {"gas":53018,"failed":false,"returnValue":"","structLogs":[
		{"pc":0,"op":"NUMBER","gas":9999946984,"gasCost":2,"depth":1,"stack":[]},
		{"pc":1,"op":"STOP","gas":9999946982,"gasCost":0,"depth":1,"stack":["0x1337"]}]}`,
				},
			}
			for _, testspec := range testSuite {
				result, err := tracingAPI.TraceCall(context.Background(), testspec.call, rpc.BlockNumberOrHash{BlockNumber: &testspec.blockNumber}, testspec.config)
				if testspec.expectErr != nil {
					Expect(err).To(HaveOccurred())
					Expect(err).To(Equal(testspec.expectErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
					var have *logger.ExecutionResult
					err := json.Unmarshal(result.(json.RawMessage), &have)
					Expect(err).ToNot(HaveOccurred())
					var want *logger.ExecutionResult
					err = json.Unmarshal([]byte(testspec.expect), &want)
					Expect(err).ToNot(HaveOccurred())
					Expect(have).To(Equal(want))
				}
			}
		})
	})

	Describe("debug_traceBlock", func() {
		It("Works", func() {
			var testSuite = []struct {
				blockNumber rpc.BlockNumber
				config      *eth.TraceConfig
				want        string
				expectErr   error
			}{
				// Trace genesis block, expect error
				{
					blockNumber: rpc.BlockNumber(0),
					expectErr:   errors.New("genesis is not traceable"),
				},
				// Trace head block
				{
					blockNumber: rpc.BlockNumber(genBlocks),
					want:        `[{"result":{"gas":21000,"failed":false,"returnValue":"","structLogs":[]}}]`,
				},
				// Trace non-existent block
				{
					blockNumber: rpc.BlockNumber(genBlocks + 1),
					expectErr:   fmt.Errorf("block #%d not found", genBlocks+1),
				},
				// Trace latest block
				{
					blockNumber: rpc.LatestBlockNumber,
					want:        `[{"result":{"gas":21000,"failed":false,"returnValue":"","structLogs":[]}}]`,
				},
				// Trace pending block
				{
					blockNumber: rpc.PendingBlockNumber,
					expectErr:   errors.New("pending block number not supported"),
				},
			}
			for _, tc := range testSuite {
				result, err := tracingAPI.TraceBlockByNumber(context.Background(), tc.blockNumber, tc.config)
				if tc.expectErr != nil {
					Expect(err).To(HaveOccurred())
					Expect(err).To(Equal(tc.expectErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
					have, _ := json.Marshal(result)
					want := tc.want
					Expect(string(have)).To(Equal(want))
				}
			}
		})
	})
})

type testBackend struct {
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	chaindb     ethdb.Database
	chain       *core.BlockChain

	refHook func() // Hook is invoked when the requested state is referenced
	relHook func() // Hook is invoked when the requested state is released
}

func (b *testBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.chain.GetHeaderByHash(hash), nil
}

func (b *testBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number == rpc.PendingBlockNumber || number == rpc.LatestBlockNumber {
		return b.chain.CurrentHeader(), nil
	}
	return b.chain.GetHeaderByNumber(uint64(number)), nil
}

func (b *testBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.chain.GetBlockByHash(hash), nil
}

func (b *testBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	if number == rpc.PendingBlockNumber || number == rpc.LatestBlockNumber {
		return b.chain.GetBlockByNumber(b.chain.CurrentBlock().Number.Uint64()), nil
	}
	return b.chain.GetBlockByNumber(uint64(number)), nil
}

func (b *testBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, hash, blockNumber, index := rawdb.ReadTransaction(b.chaindb, txHash)
	return tx, hash, blockNumber, index, nil
}

func (b *testBackend) RPCGasCap() uint64 {
	return 25000000
}

func (b *testBackend) ChainConfig() *params.ChainConfig {
	return b.chainConfig
}

func (b *testBackend) Engine() consensus.Engine {
	return b.engine
}

func (b *testBackend) ChainDb() ethdb.Database {
	return b.chaindb
}

// teardown releases the associated resources.
func (b *testBackend) teardown() {
	b.chain.Stop()
}

var (
	errStateNotFound = errors.New("state not found")
	errBlockNotFound = errors.New("block not found")
)

func (b *testBackend) StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, readOnly bool, preferDisk bool) (*state.StateDB, tracers.StateReleaseFunc, error) {
	statedb, err := b.chain.StateAt(block.Root())
	if err != nil {
		return nil, nil, errStateNotFound
	}
	if b.refHook != nil {
		b.refHook()
	}
	release := func() {
		if b.relHook != nil {
			b.relHook()
		}
	}
	return statedb, release, nil
}

func (b *testBackend) StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (*core.Message, vm.BlockContext, *state.StateDB, tracers.StateReleaseFunc, error) {
	parent := b.chain.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, vm.BlockContext{}, nil, nil, errBlockNotFound
	}
	statedb, release, err := b.StateAtBlock(ctx, parent, reexec, nil, true, false)
	if err != nil {
		return nil, vm.BlockContext{}, nil, nil, errStateNotFound
	}
	if txIndex == 0 && len(block.Transactions()) == 0 {
		return nil, vm.BlockContext{}, statedb, release, nil
	}
	// Recompute transactions up to the target index.
	signer := types.MakeSigner(b.chainConfig, block.Number())
	for idx, tx := range block.Transactions() {
		msg, _ := core.TransactionToMessage(tx, signer, block.BaseFee())
		txContext := core.NewEVMTxContext(msg)
		context := core.NewEVMBlockContext(block.Header(), b.chain, nil)
		if idx == txIndex {
			return msg, context, statedb, release, nil
		}
		vmenv := vm.NewEVM(context, txContext, statedb, b.chainConfig, vm.Config{})
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.Gas())); err != nil {
			return nil, vm.BlockContext{}, nil, nil, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))
	}
	return nil, vm.BlockContext{}, nil, nil, fmt.Errorf("transaction index %d out of range for block %#x", txIndex, block.Hash())
}

// testBackend creates a new test backend. OBS: After test is done, teardown must be
// invoked in order to release associated resources.
func newTestBackend(n int, gspec *core.Genesis, generator func(i int, b *core.BlockGen)) (*testBackend, types.Blocks, []types.Receipts) {
	backend := &testBackend{
		chainConfig: gspec.Config,
		engine:      ethash.NewFaker(),
		chaindb:     rawdb.NewMemoryDatabase(),
	}
	// Generate blocks for testing
	_, blocks, receipts := core.GenerateChainWithGenesis(gspec, backend.engine, n, generator)

	// Import the canonical chain
	cacheConfig := &core.CacheConfig{
		TrieCleanLimit:    256,
		TrieDirtyLimit:    256,
		TrieTimeLimit:     5 * time.Minute,
		SnapshotLimit:     0,
		TrieDirtyDisabled: true, // Archive mode
	}
	chain, err := core.NewBlockChain(backend.chaindb, cacheConfig, gspec, nil, backend.engine, vm.Config{}, nil, nil)
	Expect(err).ToNot(HaveOccurred())
	n, err = chain.InsertChain(blocks)
	Expect(err).ToNot(HaveOccurred())
	backend.chain = chain
	return backend, blocks, receipts
}

type Account struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

type Accounts []Account

func (a Accounts) Len() int           { return len(a) }
func (a Accounts) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Accounts) Less(i, j int) bool { return bytes.Compare(a[i].addr.Bytes(), a[j].addr.Bytes()) < 0 }

func newAccounts(n int) (accounts Accounts) {
	for i := 0; i < n; i++ {
		key, _ := crypto.GenerateKey()
		addr := crypto.PubkeyToAddress(key.PublicKey)
		accounts = append(accounts, Account{key: key, addr: addr})
	}
	sort.Sort(accounts)
	return accounts
}
