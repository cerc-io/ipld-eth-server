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

package eth_state_test

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"os"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth/test_helpers"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/shared"
)

var (
	parsedABI     abi.ABI
	randomAddress = common.HexToAddress("0x9F4203bd7a11aCB94882050E6f1C3ab14BBaD3D9")
	randomHash    = crypto.Keccak256Hash(randomAddress.Bytes())
	number        = rpc.BlockNumber(test_helpers.BlockNumber.Int64())

	block1StateRoot    = common.HexToHash("0xa1f614839ebdd58677df2c9d66a3e0acc9462acc49fad6006d0b6e5d2b98ed21")
	rootDataHashBlock1 = "a1f614839ebdd58677df2c9d66a3e0acc9462acc49fad6006d0b6e5d2b98ed21"
	rootDataBlock1     = "f871a0577652b625b77bdb5bf77bc43f3125cad7464d679d1575565277d3611b8053e780808080a0fe889f10e5db8f2c2bf355928152a17f6e3bb99a9241ac6d84c77e6264509c798080808080808080a011db0cda34a896dabeb6839bb06a38f49514cfa486435984eb013b7df9ee85c58080"

	block5StateRoot    = common.HexToHash("0x572ef3b6b3d5164ed9d83341073f13af4d60a3aab38989b6c03917544f186a43")
	rootDataHashBlock5 = "572ef3b6b3d5164ed9d83341073f13af4d60a3aab38989b6c03917544f186a43"
	rootDataBlock5     = "f8b1a0408dd81f6cd5c614f91ecd9faa01d5feba936e0314ba04f99c74069ba819e0f280808080a0b356351d60bc9894cf1f1d6cb68c815f0131d50f1da83c4023a09ec855cfff91a0180d554b171f6acf8295e376266df2311f68975d74c02753b85707d308f703e48080808080a0422c7cc4fa407603f0879a0ecaa809682ce98dbef30551a34bcce09fa3ac995180a02d264f591aa3fa9df3cbeea190a4fd8d5483ddfb1b85603b2a006d179f79ba358080"

	account1DataHash     = "180d554b171f6acf8295e376266df2311f68975d74c02753b85707d308f703e4"
	account1Data         = "f869a03114658a74d9cc9f7acf2c5cd696c3494d7c344d78bfec3add0d91ec4e8d1c45b846f8440180a04bd45c41d863f1bcf5da53364387fcdd64f77924d388a4df47e64132273fb4c0a0ba79854f3dbf6505fdbb085888e25fae8fa97288c5ce8fcd39aa589290d9a659"
	account1StateLeafKey = "0x6114658a74d9cc9f7acf2c5cd696c3494d7c344d78bfec3add0d91ec4e8d1c45"
	account1Code         = "608060405234801561001057600080fd5b50600436106100415760003560e01c806343d726d61461004657806365f3c31a1461005057806373d4a13a1461007e575b600080fd5b61004e61009c565b005b61007c6004803603602081101561006657600080fd5b810190808035906020019092919050505061017b565b005b610086610185565b6040518082815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610141576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602281526020018061018c6022913960400191505060405180910390fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b8060018190555050565b6001548156fe4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6e2ea265627a7a723158205ba91466129f45285f53176d805117208c231ec6343d7896790e6fc4165b802b64736f6c63430005110032"
	account2DataHash     = "2d264f591aa3fa9df3cbeea190a4fd8d5483ddfb1b85603b2a006d179f79ba35"
	account2Data         = "f871a03926db69aaced518e9b9f0f434a473e7174109c943548bb8f23be41ca76d9ad2b84ef84c02881bc16d674ec82710a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	account3DataHash     = "408dd81f6cd5c614f91ecd9faa01d5feba936e0314ba04f99c74069ba819e0f2"
	account3Data         = "f86da030bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2ab84af848058405f5b608a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	account4DataHash     = "422c7cc4fa407603f0879a0ecaa809682ce98dbef30551a34bcce09fa3ac9951"
	account4Data         = "f871a03957f3e2f04a0764c3a0491b175f69926da61efbcc8f61fa1455fd2d2b4cdd45b84ef84c80883782dace9d9003e8a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	account5DataHash     = "b356351d60bc9894cf1f1d6cb68c815f0131d50f1da83c4023a09ec855cfff91"
	account5Data         = "f871a03380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab84ef84c80883782dace9d900000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

	contractStorageRootBlock5 = common.HexToHash("0x4bd45c41d863f1bcf5da53364387fcdd64f77924d388a4df47e64132273fb4c0")
	storageRootDataHashBlock5 = "4bd45c41d863f1bcf5da53364387fcdd64f77924d388a4df47e64132273fb4c0"
	storageRootDataBlock5     = "f838a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594703c4b2bd70c169f5717101caee543299fc946c7"

	contractStorageRootBlock4 = common.HexToHash("0x64ad893aa7937d05983daa8b7d221acdf1c116433f29dcd1ea69f16fa96fce68")
	storageRootDataHashBlock4 = "64ad893aa7937d05983daa8b7d221acdf1c116433f29dcd1ea69f16fa96fce68"
	storageRootDataBlock4     = "f8518080a08e8ada45207a7d2f19dd6f0ee4955cec64fa5ebef29568b5c449a4c4dd361d558080808080808080a07b58866e3801680bea90c82a80eb08889ececef107b8b504ae1d1a1e1e17b7af8080808080"

	storageNode1DataHash = "7b58866e3801680bea90c82a80eb08889ececef107b8b504ae1d1a1e1e17b7af"
	storageNode1Data     = "e2a0310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf609"
	storageNode2DataHash = "8e8ada45207a7d2f19dd6f0ee4955cec64fa5ebef29568b5c449a4c4dd361d55"
	storageNode2Data     = "f7a0390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594703c4b2bd70c169f5717101caee543299fc946c7"
)

func init() {
	// load abi
	abiBytes, err := os.ReadFile("../test_helpers/abi.json")
	if err != nil {
		panic(err)
	}
	parsedABI, err = abi.JSON(bytes.NewReader(abiBytes))
	if err != nil {
		panic(err)
	}
}

const chainLength = 5

var (
	blocks                  []*types.Block
	receipts                []types.Receipts
	chain                   *core.BlockChain
	db                      *sqlx.DB
	api                     *eth.PublicEthAPI
	backend                 *eth.Backend
	chainConfig             = &*params.TestChainConfig
	mockTD                  = big.NewInt(1337)
	expectedCanonicalHeader map[string]interface{}
	ctx                     = context.Background()
)

var _ = BeforeSuite(func() {
	chainConfig.LondonBlock = big.NewInt(100)

	// db and type initializations
	var err error
	db = shared.SetupDB()

	backend, err = eth.NewEthBackend(db, &eth.Config{
		ChainConfig: chainConfig,
		VMConfig:    vm.Config{},
		RPCGasCap:   big.NewInt(10000000000), // Max gas capacity for a rpc call.
		GroupCacheConfig: &shared.GroupCacheConfig{
			StateDB: shared.GroupConfig{
				Name:                   "eth_state_test",
				CacheSizeInMB:          8,
				CacheExpiryInMins:      60,
				LogStatsIntervalInSecs: 0,
			},
		},
	})
	Expect(err).ToNot(HaveOccurred())
	api, _ = eth.NewPublicEthAPI(backend, nil, eth.APIConfig{StateDiffTimeout: shared.DefaultStateDiffTimeout})

	// make the test blockchain (and state)
	blocks, receipts, chain = test_helpers.MakeChain(chainLength, test_helpers.Genesis, test_helpers.TestChainGen, chainConfig)

	transformer := shared.SetupTestStateDiffIndexer(ctx, chainConfig, test_helpers.Genesis.Hash())
	params := statediff.Params{}
	canonicalHeader := blocks[1].Header()
	expectedCanonicalHeader = map[string]interface{}{
		"number":           (*hexutil.Big)(canonicalHeader.Number),
		"hash":             canonicalHeader.Hash(),
		"parentHash":       canonicalHeader.ParentHash,
		"nonce":            canonicalHeader.Nonce,
		"mixHash":          canonicalHeader.MixDigest,
		"sha3Uncles":       canonicalHeader.UncleHash,
		"logsBloom":        canonicalHeader.Bloom,
		"stateRoot":        canonicalHeader.Root,
		"miner":            canonicalHeader.Coinbase,
		"difficulty":       (*hexutil.Big)(canonicalHeader.Difficulty),
		"extraData":        hexutil.Bytes([]byte{}),
		"size":             hexutil.Uint64(canonicalHeader.Size()),
		"gasLimit":         hexutil.Uint64(canonicalHeader.GasLimit),
		"gasUsed":          hexutil.Uint64(canonicalHeader.GasUsed),
		"timestamp":        hexutil.Uint64(canonicalHeader.Time),
		"transactionsRoot": canonicalHeader.TxHash,
		"receiptsRoot":     canonicalHeader.ReceiptHash,
		"totalDifficulty":  (*hexutil.Big)(mockTD),
	}

	// Insert some non-canonical data into the database so that we test our ability to discern canonicity
	// NOTE: Nan-canonical blocks must come first, because the statediffer will assume the most recent block it is
	// provided at a certain height is canonical.  This is true inside geth, but not necessarily inside this test.
	indexAndPublisher := shared.SetupTestStateDiffIndexer(ctx, chainConfig, test_helpers.Genesis.Hash())

	tx, err := indexAndPublisher.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
	Expect(err).ToNot(HaveOccurred())
	defer tx.RollbackOnFailure(err)

	err = tx.Submit()
	Expect(err).ToNot(HaveOccurred())

	// The non-canonical header has a child
	tx, err = indexAndPublisher.PushBlock(test_helpers.MockChild, test_helpers.MockReceipts, test_helpers.MockChild.Difficulty())
	Expect(err).ToNot(HaveOccurred())
	defer tx.RollbackOnFailure(err)

	err = tx.Submit()
	Expect(err).ToNot(HaveOccurred())

	// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
	builder := statediff.NewBuilder(adapt.GethStateView(chain.StateCache()))
	for i, block := range blocks {
		var args statediff.Args
		var rcts types.Receipts
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
			rcts = receipts[i-1]
		}
		diff, err := builder.BuildStateDiffObject(args, params)
		Expect(err).ToNot(HaveOccurred())
		tx, err := transformer.PushBlock(block, rcts, mockTD)
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

})

var _ = AfterSuite(func() {
	shared.TearDownDB(db)
	chain.Stop()
})

var _ = Describe("eth state reading tests", func() {

	Describe("eth_call", func() {
		It("Applies call args (tx data) on top of state, returning the result (e.g. a Getter method call)", func() {
			data, err := parsedABI.Pack("data")
			Expect(err).ToNot(HaveOccurred())
			bdata := hexutil.Bytes(data)
			callArgs := eth.CallArgs{
				To:   &test_helpers.ContractAddr,
				Data: &bdata,
			}

			// Before contract deployment, returns nil
			res, err := api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(0), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(res).To(BeNil())

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(1), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(res).To(BeNil())

			// After deployment
			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(2), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes := hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(3), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(4), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000009"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(5), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))
			Expect(res).To(Equal(expectedRes))
		})
	})

	Describe("eth_getBalance", func() {
		var (
			expectedContractBalance   = (*hexutil.Big)(common.Big0)
			expectedBankBalanceBlock0 = (*hexutil.Big)(test_helpers.TestBankFunds)

			expectedAcct1BalanceBlock1 = (*hexutil.Big)(big.NewInt(10000))
			expectedBankBalanceBlock1  = (*hexutil.Big)(new(big.Int).Sub(test_helpers.TestBankFunds, big.NewInt(10000)))

			expectedAcct2BalanceBlock2 = (*hexutil.Big)(big.NewInt(1000))
			expectedBankBalanceBlock2  = (*hexutil.Big)(new(big.Int).Sub(expectedBankBalanceBlock1.ToInt(), big.NewInt(1000)))

			expectedAcct2BalanceBlock3 = (*hexutil.Big)(new(big.Int).Add(expectedAcct2BalanceBlock2.ToInt(), test_helpers.MiningReward))

			expectedAcct2BalanceBlock4 = (*hexutil.Big)(new(big.Int).Add(expectedAcct2BalanceBlock3.ToInt(), test_helpers.MiningReward))

			expectedAcct1BalanceBlock5 = (*hexutil.Big)(new(big.Int).Add(expectedAcct1BalanceBlock1.ToInt(), test_helpers.MiningReward))
		)

		It("Retrieves account balance by block number", func() {
			bal, err := api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock0))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock3))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock5))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))
		})
		It("Retrieves account balance by block hash", func() {
			bal, err := api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock0))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			_, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())

			Expect(bal).To(Equal(expectedAcct2BalanceBlock2))
			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock3))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock5))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))
		})
		It("Returns 0 if account balance not found by block number", func() {
			bal, err := api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))
		})
		It("Returns 0 if account balance not found by block hash", func() {
			bal, err := api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))
		})
	})

	Describe("eth_getCode", func() {
		It("Retrieves the code for the provided contract address at the block with the provided number", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))

			code, err = api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))
		})
		It("Retrieves the code for the provided contract address at the block with the provided hash", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))

			code, err = api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))
		})
		It("Returns `nil` for an account it cannot find the code for", func() {
			code, err := api.GetCode(ctx, randomAddress, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(BeEmpty())
		})
		It("Returns `nil`  for a contract that doesn't exist at this height", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(BeEmpty())
		})
	})

	Describe("eth_getStorageAt", func() {
		It("Returns empty slice if it tries to access a contract which does not exist", func() {
			storage, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.ContractSlotKeyHash.Hex(), rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).NotTo(HaveOccurred())
			Expect(storage).To(Equal(hexutil.Bytes(eth.EmptyNodeValue)))

			storage, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.ContractSlotKeyHash.Hex(), rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).NotTo(HaveOccurred())
			Expect(storage).To(Equal(hexutil.Bytes(eth.EmptyNodeValue)))
		})
		It("Returns empty slice if it tries to access a contract slot which does not exist", func() {
			storage, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, randomHash.Hex(), rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).NotTo(HaveOccurred())
			Expect(storage).To(Equal(hexutil.Bytes(eth.EmptyNodeValue)))
		})
		It("Retrieves the storage value at the provided contract address and storage leaf key at the block with the provided hash or number", func() {
			// After deployment
			val, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			expectedRes := hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
			Expect(val).To(Equal(expectedRes))

			val, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"))
			Expect(val).To(Equal(expectedRes))

			val, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000009"))
			Expect(val).To(Equal(expectedRes))

			val, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(hexutil.Bytes(eth.EmptyNodeValue)))
		})
		It("Throws an error for a non-existing block hash", func() {
			_, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithHash(randomHash, true))
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("header for hash not found"))
		})
		It("Throws an error for a non-existing block number", func() {
			_, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(chainLength+1))
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("header not found"))
		})
	})

	Describe("eth_getHeaderByNumber", func() {
		It("Finds the canonical header based on the header's weight relative to others at the provided height", func() {
			header, err := api.GetHeaderByNumber(ctx, number)
			Expect(err).ToNot(HaveOccurred())
			Expect(header).To(Equal(expectedCanonicalHeader))
		})
	})

	Describe("eth_getSlice", func() {
		It("Retrieves the state slice for root path", func() {
			path := "0x"
			depth := 3
			sliceResponse, err := api.GetSlice(ctx, path, depth, block5StateRoot, false)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, block5StateRoot.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "1",
						"01-max-depth":           "1",
						"02-total-trie-nodes":    "6",
						"03-leaves":              "5",
						"04-smart-contracts":     "1",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{},
					Head: map[string]string{
						rootDataHashBlock5: rootDataBlock5,
					},
					Slice: map[string]string{
						account1DataHash: account1Data,
						account2DataHash: account2Data,
						account3DataHash: account3Data,
						account4DataHash: account4Data,
						account5DataHash: account5Data,
					},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{
					account1StateLeafKey: {
						StorageRoot: contractStorageRootBlock5.Hex(),
						EVMCode:     account1Code,
					},
				},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
		It("Retrieves the state slice for root path with 0 depth", func() {
			path := "0x"
			depth := 0
			sliceResponse, err := api.GetSlice(ctx, path, depth, block5StateRoot, false)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, block5StateRoot.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "1",
						"01-max-depth":           "0",
						"02-total-trie-nodes":    "1",
						"03-leaves":              "0",
						"04-smart-contracts":     "0",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{},
					Head: map[string]string{
						rootDataHashBlock5: rootDataBlock5,
					},
					Slice: map[string]string{},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
		It("Retrieves the state slice for a path to an account", func() {
			path := "0x06"
			depth := 2
			sliceResponse, err := api.GetSlice(ctx, path, depth, block5StateRoot, false)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, block5StateRoot.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "2",
						"01-max-depth":           "0",
						"02-total-trie-nodes":    "2",
						"03-leaves":              "1",
						"04-smart-contracts":     "1",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{
						rootDataHashBlock5: rootDataBlock5,
					},
					Head: map[string]string{
						account1DataHash: account1Data,
					},
					Slice: map[string]string{},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{
					account1StateLeafKey: {
						StorageRoot: contractStorageRootBlock5.Hex(),
						EVMCode:     account1Code,
					},
				},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
		It("Retrieves the state slice for a path to a non-existing account", func() {
			path := "0x06"
			depth := 2
			sliceResponse, err := api.GetSlice(ctx, path, depth, block1StateRoot, false)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, block1StateRoot.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "1",
						"01-max-depth":           "0",
						"02-total-trie-nodes":    "1",
						"03-leaves":              "0",
						"04-smart-contracts":     "0",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{
						rootDataHashBlock1: rootDataBlock1,
					},
					Head:  map[string]string{},
					Slice: map[string]string{},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})

		It("Retrieves the storage slice for root path", func() {
			path := "0x"
			depth := 2
			sliceResponse, err := api.GetSlice(ctx, path, depth, contractStorageRootBlock4, true)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, contractStorageRootBlock4.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "1",
						"01-max-depth":           "1",
						"02-total-trie-nodes":    "3",
						"03-leaves":              "2",
						"04-smart-contracts":     "0",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{},
					Head: map[string]string{
						storageRootDataHashBlock4: storageRootDataBlock4,
					},
					Slice: map[string]string{
						storageNode1DataHash: storageNode1Data,
						storageNode2DataHash: storageNode2Data,
					},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
		It("Retrieves the storage slice for root path with 0 depth", func() {
			path := "0x"
			depth := 0
			sliceResponse, err := api.GetSlice(ctx, path, depth, contractStorageRootBlock4, true)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, contractStorageRootBlock4.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "1",
						"01-max-depth":           "0",
						"02-total-trie-nodes":    "1",
						"03-leaves":              "0",
						"04-smart-contracts":     "0",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{},
					Head: map[string]string{
						storageRootDataHashBlock4: storageRootDataBlock4,
					},
					Slice: map[string]string{},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
		It("Retrieves the storage slice for root path with deleted nodes", func() {
			path := "0x"
			depth := 2
			sliceResponse, err := api.GetSlice(ctx, path, depth, contractStorageRootBlock5, true)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, contractStorageRootBlock5.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "1",
						"01-max-depth":           "0",
						"02-total-trie-nodes":    "1",
						"03-leaves":              "1",
						"04-smart-contracts":     "0",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{},
					Head: map[string]string{
						storageRootDataHashBlock5: storageRootDataBlock5,
					},
					Slice: map[string]string{},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
		It("Retrieves the storage slice for a path to a storage node", func() {
			path := "0x0b"
			depth := 2
			sliceResponse, err := api.GetSlice(ctx, path, depth, contractStorageRootBlock4, true)
			Expect(err).ToNot(HaveOccurred())

			expectedResponse := eth.GetSliceResponse{
				SliceID: fmt.Sprintf("%s-%d-%s", path, depth, contractStorageRootBlock4.String()),
				MetaData: eth.GetSliceResponseMetadata{
					NodeStats: map[string]string{
						"00-stem-and-head-nodes": "2",
						"01-max-depth":           "0",
						"02-total-trie-nodes":    "2",
						"03-leaves":              "1",
						"04-smart-contracts":     "0",
					},
				},
				TrieNodes: eth.GetSliceResponseTrieNodes{
					Stem: map[string]string{
						storageRootDataHashBlock4: storageRootDataBlock4,
					},
					Head: map[string]string{
						storageNode1DataHash: storageNode1Data,
					},
					Slice: map[string]string{},
				},
				Leaves: map[string]eth.GetSliceResponseAccount{},
			}

			CheckGetSliceResponse(*sliceResponse, expectedResponse)
		})
	})
})
