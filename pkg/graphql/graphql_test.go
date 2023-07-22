// VulcanizeDB
// Copyright © 2020 Vulcanize

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

package graphql_test

import (
	"context"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/ethereum/go-ethereum/statediff/indexer/ipld"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth/test_helpers"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/graphql"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/shared"
)

const (
	gqlEndPoint = "127.0.0.1:8083"
)

var (
	randomAddr              = common.HexToAddress("0x1C3ab14BBaD3D99F4203bd7a11aCB94882050E6f")
	randomHash              = crypto.Keccak256Hash(randomAddr.Bytes())
	blocks                  []*types.Block
	receipts                []types.Receipts
	chain                   *core.BlockChain
	db                      *sqlx.DB
	backend                 *eth.Backend
	graphQLServer           *graphql.Service
	chainConfig             = &*params.TestChainConfig
	client                  = graphql.NewClient(fmt.Sprintf("http://%s/graphql", gqlEndPoint))
	mockTD                  = big.NewInt(1337)
	ctx                     = context.Background()
	nonCanonBlockHash       common.Hash
	nonCanonContractAddress common.Address
)

var _ = BeforeSuite(func() {
	var err error
	db = shared.SetupDB()

	backend, err = eth.NewEthBackend(db, &eth.Config{
		ChainConfig: chainConfig,
		VMConfig:    vm.Config{},
		RPCGasCap:   big.NewInt(10000000000),
		GroupCacheConfig: &shared.GroupCacheConfig{
			StateDB: shared.GroupConfig{
				Name:                   "graphql_test",
				CacheSizeInMB:          8,
				CacheExpiryInMins:      60,
				LogStatsIntervalInSecs: 0,
			},
		},
	})
	Expect(err).ToNot(HaveOccurred())

	// make the test blockchain (and state)
	chainConfig.LondonBlock = big.NewInt(100)
	blocks, receipts, chain = test_helpers.MakeChain(5, test_helpers.Genesis, test_helpers.TestChainGen, chainConfig)
	indexer := shared.SetupTestStateDiffIndexer(context.Background(), chainConfig, test_helpers.Genesis.Hash())
	builder := statediff.NewBuilder(chain.StateCache())

	// Insert some non-canonical data into the database so that we test our ability to discern canonicity
	nonCanonBlockHash = test_helpers.MockBlock.Hash()
	nonCanonContractAddress = test_helpers.ContractAddr

	tx, err := indexer.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
	Expect(err).ToNot(HaveOccurred())

	err = tx.Submit(err)
	Expect(err).ToNot(HaveOccurred())

	// The non-canonical header has a child
	tx, err = indexer.PushBlock(test_helpers.MockChild, test_helpers.MockReceipts, test_helpers.MockChild.Difficulty())
	Expect(err).ToNot(HaveOccurred())

	ipld := sdtypes.IPLD{
		CID:     ipld.Keccak256ToCid(ipld.RawBinary, test_helpers.CodeHash.Bytes()).String(),
		Content: test_helpers.ContractCode,
	}
	err = indexer.PushIPLD(tx, ipld)
	Expect(err).ToNot(HaveOccurred())

	err = tx.Submit(err)
	Expect(err).ToNot(HaveOccurred())

	// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
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

		_, err = builder.BuildStateDiffObject(args, statediff.Params{})
		Expect(err).ToNot(HaveOccurred())
		tx, err := indexer.PushBlock(block, rcts, mockTD)
		Expect(err).ToNot(HaveOccurred())

		err = tx.Submit(err)
		Expect(err).ToNot(HaveOccurred())
	}

	graphQLServer, err = graphql.New(backend, gqlEndPoint, nil, []string{"*"}, rpc.HTTPTimeouts{})
	Expect(err).ToNot(HaveOccurred())

	err = graphQLServer.Start(nil)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	err := graphQLServer.Stop()
	Expect(err).ToNot(HaveOccurred())
	shared.TearDownDB(db)
	chain.Stop()
})

var _ = Describe("GraphQL", func() {
	Describe("eth_getLogs", func() {
		It("Retrieves logs that matches the provided blockHash and contract address", func() {
			logs, err := client.GetLogs(ctx, nonCanonBlockHash, []common.Address{nonCanonContractAddress})
			Expect(err).ToNot(HaveOccurred())

			expectedLogs := []graphql.LogResponse{
				{
					Topics:      test_helpers.MockLog1.Topics,
					Data:        hexutil.Bytes(test_helpers.MockLog1.Data),
					Transaction: graphql.TransactionResponse{Hash: test_helpers.MockTransactions[0].Hash()},
					ReceiptCID:  test_helpers.Rct1CID.String(),
					Status:      int32(test_helpers.MockReceipts[0].Status),
				},
			}

			Expect(logs).To(Equal(expectedLogs))
		})

		It("Retrieves logs for the failed receipt status that matches the provided blockHash and another contract address", func() {
			logs, err := client.GetLogs(ctx, nonCanonBlockHash, []common.Address{test_helpers.AnotherAddress2})
			Expect(err).ToNot(HaveOccurred())

			expectedLogs := []graphql.LogResponse{
				{
					Topics:      test_helpers.MockLog6.Topics,
					Data:        hexutil.Bytes(test_helpers.MockLog6.Data),
					Transaction: graphql.TransactionResponse{Hash: test_helpers.MockTransactions[3].Hash()},
					ReceiptCID:  test_helpers.Rct4CID.String(),
					Status:      int32(test_helpers.MockReceipts[3].Status),
				},
			}

			Expect(logs).To(Equal(expectedLogs))
		})

		It("Retrieves logs that matches the provided blockHash and multiple contract addresses", func() {
			logs, err := client.GetLogs(ctx, nonCanonBlockHash, []common.Address{nonCanonContractAddress, test_helpers.AnotherAddress2})
			Expect(err).ToNot(HaveOccurred())

			expectedLogs := []graphql.LogResponse{
				{
					Topics:      test_helpers.MockLog1.Topics,
					Data:        hexutil.Bytes(test_helpers.MockLog1.Data),
					Transaction: graphql.TransactionResponse{Hash: test_helpers.MockTransactions[0].Hash()},
					ReceiptCID:  test_helpers.Rct1CID.String(),
					Status:      int32(test_helpers.MockReceipts[0].Status),
				},
				{
					Topics:      test_helpers.MockLog6.Topics,
					Data:        hexutil.Bytes(test_helpers.MockLog6.Data),
					Transaction: graphql.TransactionResponse{Hash: test_helpers.MockTransactions[3].Hash()},
					ReceiptCID:  test_helpers.Rct4CID.String(),
					Status:      int32(test_helpers.MockReceipts[3].Status),
				},
			}

			Expect(logs).To(Equal(expectedLogs))
		})

		It("Retrieves all the logs for the receipt that matches the provided blockHash and nil contract address", func() {
			logs, err := client.GetLogs(ctx, nonCanonBlockHash, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(6))
		})

		It("Retrieves logs with random hash", func() {
			logs, err := client.GetLogs(ctx, randomHash, []common.Address{nonCanonContractAddress})
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(0))
		})
	})

	Describe("eth_getStorageAt", func() {
		It("Retrieves the storage value at the provided contract address and storage leaf key at the block with the provided hash", func() {
			storageRes, err := client.GetStorageAt(ctx, blocks[2].Hash(), nonCanonContractAddress, test_helpers.IndexOne)
			Expect(err).ToNot(HaveOccurred())
			Expect(storageRes.Value).To(Equal(common.HexToHash("01")))

			storageRes, err = client.GetStorageAt(ctx, blocks[3].Hash(), nonCanonContractAddress, test_helpers.IndexOne)
			Expect(err).ToNot(HaveOccurred())
			Expect(storageRes.Value).To(Equal(common.HexToHash("03")))

			storageRes, err = client.GetStorageAt(ctx, blocks[4].Hash(), nonCanonContractAddress, test_helpers.IndexOne)
			Expect(err).ToNot(HaveOccurred())
			Expect(storageRes.Value).To(Equal(common.HexToHash("09")))
		})

		It("Retrieves empty data if it tries to access a contract at a blockHash which does not exist", func() {
			storageRes, err := client.GetStorageAt(ctx, blocks[0].Hash(), nonCanonContractAddress, test_helpers.IndexOne)
			Expect(err).ToNot(HaveOccurred())
			Expect(storageRes.Value).To(Equal(common.Hash{}))

			storageRes, err = client.GetStorageAt(ctx, blocks[1].Hash(), nonCanonContractAddress, test_helpers.IndexOne)
			Expect(err).ToNot(HaveOccurred())
			Expect(storageRes.Value).To(Equal(common.Hash{}))
		})

		It("Retrieves empty data if it tries to access a contract slot which does not exist", func() {
			storageRes, err := client.GetStorageAt(ctx, blocks[3].Hash(), nonCanonContractAddress, randomHash.Hex())
			Expect(err).ToNot(HaveOccurred())
			Expect(storageRes.Value).To(Equal(common.Hash{}))
		})
	})

	Describe("allEthHeaderCids", func() {
		It("Retrieves header_cids that matches the provided blockNumber", func() {
			allEthHeaderCIDsResp, err := client.AllEthHeaderCIDs(ctx, graphql.EthHeaderCIDCondition{BlockNumber: new(graphql.BigInt).SetUint64(2)})
			Expect(err).ToNot(HaveOccurred())

			headerCIDs, err := backend.Retriever.RetrieveHeaderAndTxCIDsByBlockNumber(2)
			Expect(err).ToNot(HaveOccurred())

			for idx, headerCID := range headerCIDs {
				ethHeaderCID := allEthHeaderCIDsResp.Nodes[idx]

				compareEthHeaderCID(ethHeaderCID, headerCID)
			}
		})

		It("Retrieves header_cids that matches the provided blockHash", func() {
			blockHash := blocks[1].Hash().String()
			allEthHeaderCIDsResp, err := client.AllEthHeaderCIDs(ctx, graphql.EthHeaderCIDCondition{BlockHash: &blockHash})
			Expect(err).ToNot(HaveOccurred())

			headerCID, err := backend.Retriever.RetrieveHeaderAndTxCIDsByBlockHash(blocks[1].Hash(), nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(allEthHeaderCIDsResp.Nodes)).To(Equal(1))
			ethHeaderCID := allEthHeaderCIDsResp.Nodes[0]
			compareEthHeaderCID(ethHeaderCID, headerCID)
		})
	})

	Describe("ethTransactionCidByTxHash", func() {
		It("Retrieves tx_cid that matches the provided txHash", func() {
			txHash := blocks[2].Transactions()[0].Hash().String()
			ethTransactionCIDResp, err := client.EthTransactionCIDByTxHash(ctx, txHash)
			Expect(err).ToNot(HaveOccurred())

			txCID, err := backend.Retriever.RetrieveTxCIDByHash(txHash, nil)
			Expect(err).ToNot(HaveOccurred())

			compareEthTxCID(*ethTransactionCIDResp, txCID)

			Expect(ethTransactionCIDResp.BlockByCid.Data).To(Equal(graphql.Bytes(txCID.IPLD.Data).String()))
		})
	})
})

func compareEthHeaderCID(ethHeaderCID graphql.EthHeaderCIDResponse, headerCID eth.HeaderCIDRecord) {
	blockNumber, err := strconv.ParseInt(headerCID.BlockNumber, 10, 64)
	Expect(err).ToNot(HaveOccurred())

	td, err := strconv.ParseInt(headerCID.TotalDifficulty, 10, 64)
	Expect(err).ToNot(HaveOccurred())

	Expect(ethHeaderCID.CID).To(Equal(headerCID.CID))
	Expect(ethHeaderCID.BlockNumber).To(Equal(*new(graphql.BigInt).SetUint64(uint64(blockNumber))))
	Expect(ethHeaderCID.BlockHash).To(Equal(headerCID.BlockHash))
	Expect(ethHeaderCID.ParentHash).To(Equal(headerCID.ParentHash))
	Expect(ethHeaderCID.Timestamp).To(Equal(*new(graphql.BigInt).SetUint64(headerCID.Timestamp)))
	Expect(ethHeaderCID.StateRoot).To(Equal(headerCID.StateRoot))
	Expect(ethHeaderCID.Td).To(Equal(*new(graphql.BigInt).SetUint64(uint64(td))))
	Expect(ethHeaderCID.TxRoot).To(Equal(headerCID.TxRoot))
	Expect(ethHeaderCID.ReceiptRoot).To(Equal(headerCID.RctRoot))
	Expect(ethHeaderCID.UncleRoot).To(Equal(headerCID.UnclesHash))
	Expect(ethHeaderCID.Bloom).To(Equal(graphql.Bytes(headerCID.Bloom).String()))

	for tIdx, txCID := range headerCID.TransactionCIDs {
		ethTxCID := ethHeaderCID.EthTransactionCIDsByHeaderId.Nodes[tIdx]
		compareEthTxCID(ethTxCID, txCID)
	}

	Expect(ethHeaderCID.BlockByCid.Data).To(Equal(graphql.Bytes(headerCID.IPLD.Data).String()))
	Expect(ethHeaderCID.BlockByCid.Key).To(Equal(headerCID.IPLD.Key))
}

func compareEthTxCID(ethTxCID graphql.EthTransactionCIDResponse, txCID eth.TransactionCIDRecord) {
	Expect(ethTxCID.CID).To(Equal(txCID.CID))
	Expect(ethTxCID.TxHash).To(Equal(txCID.TxHash))
	Expect(ethTxCID.Index).To(Equal(int32(txCID.Index)))
	Expect(ethTxCID.Src).To(Equal(txCID.Src))
	Expect(ethTxCID.Dst).To(Equal(txCID.Dst))
}
