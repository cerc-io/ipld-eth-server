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

package eth_test

import (
	"math/big"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth/test_helpers"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/shared"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/statediff/indexer/interfaces"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/jmoiron/sqlx"
)

var (
	openFilter = eth.SubscriptionSettings{
		Start:         big.NewInt(0),
		End:           big.NewInt(1),
		HeaderFilter:  eth.HeaderFilter{},
		TxFilter:      eth.TxFilter{},
		ReceiptFilter: eth.ReceiptFilter{},
		StateFilter:   eth.StateFilter{},
		StorageFilter: eth.StorageFilter{},
	}
	rctAddressFilter = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			LogAddresses: []string{test_helpers.Address.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctTopicsFilter = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			Topics: [][]string{{"0x0000000000000000000000000000000000000000000000000000000000000004"}},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctTopicsAndAddressFilter = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			Topics: [][]string{
				{"0x0000000000000000000000000000000000000000000000000000000000000004"},
				{"0x0000000000000000000000000000000000000000000000000000000000000006"},
			},
			LogAddresses: []string{test_helpers.Address.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctTopicsAndAddressFilterFail = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			Topics: [][]string{
				{"0x0000000000000000000000000000000000000000000000000000000000000004"},
				{"0x0000000000000000000000000000000000000000000000000000000000000007"}, // This topic won't match on the mocks.Address.String() contract receipt
			},
			LogAddresses: []string{test_helpers.Address.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctAddressesAndTopicFilter = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			Topics:       [][]string{{"0x0000000000000000000000000000000000000000000000000000000000000005"}},
			LogAddresses: []string{test_helpers.Address.String(), test_helpers.AnotherAddress.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctsForAllCollectedTrxs = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{}, // Trx filter open so we will collect all trxs, therefore we will also collect all corresponding rcts despite rct filter
		ReceiptFilter: eth.ReceiptFilter{
			MatchTxs:     true,
			Topics:       [][]string{{"0x0000000000000000000000000000000000000000000000000000000000000006"}}, // Topic0 isn't one of the topic0s we have
			LogAddresses: []string{"0x0000000000000000000000000000000000000002"},                             // Contract isn't one of the contracts we have
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctsForSelectCollectedTrxs = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Dst: []string{test_helpers.AnotherAddress.String()}, // We only filter for one of the trxs so we will only get the one corresponding receipt
		},
		ReceiptFilter: eth.ReceiptFilter{
			MatchTxs:     true,
			Topics:       [][]string{{"0x0000000000000000000000000000000000000000000000000000000000000006"}}, // Topic0 isn't one of the topic0s we have
			LogAddresses: []string{"0x0000000000000000000000000000000000000002"},                             // Contract isn't one of the contracts we have
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	stateFilter = eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			Off: true,
		},
		StateFilter: eth.StateFilter{
			Addresses: []string{test_helpers.AccountAddresss.Hex()},
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
)

var _ = Describe("Retriever", func() {
	var (
		db          *sqlx.DB
		diffIndexer interfaces.StateDiffIndexer
		retriever   *eth.CIDRetriever
	)
	BeforeEach(func() {
		db = shared.SetupDB()
		diffIndexer = shared.SetupTestStateDiffIndexer(ctx, params.TestChainConfig, test_helpers.Genesis.Hash())

		retriever = eth.NewCIDRetriever(db)
	})
	AfterEach(func() {
		shared.TearDownDB(db)
	})

	Describe("Retrieve", func() {
		BeforeEach(func() {
			tx, err := diffIndexer.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
			Expect(err).ToNot(HaveOccurred())
			for _, node := range test_helpers.MockStateNodes {
				err = diffIndexer.PushStateNode(tx, node, test_helpers.MockBlock.Hash().String())
				Expect(err).ToNot(HaveOccurred())
			}

			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())
		})
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {
			type rctCIDAndMHKeyResult struct {
				LeafCID   string `db:"leaf_cid"`
				LeafMhKey string `db:"leaf_mh_key"`
			}
			expectedRctCIDsAndLeafNodes := make([]rctCIDAndMHKeyResult, 0)
			pgStr := `SELECT receipt_cids.leaf_cid, receipt_cids.leaf_mh_key FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
				WHERE receipt_cids.tx_id = transaction_cids.tx_hash
				AND transaction_cids.header_id = header_cids.block_hash
				AND header_cids.block_number = $1
				ORDER BY transaction_cids.index`
			err := db.Select(&expectedRctCIDsAndLeafNodes, pgStr, test_helpers.BlockNumber.Uint64())
			Expect(err).ToNot(HaveOccurred())
			cids, empty, err := retriever.Retrieve(openFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids)).To(Equal(1))
			Expect(cids[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))

			expectedHeaderCID := test_helpers.MockCIDWrapper.Header
			expectedHeaderCID.BlockHash = cids[0].Header.BlockHash
			expectedHeaderCID.NodeID = cids[0].Header.NodeID
			Expect(cids[0].Header).To(Equal(expectedHeaderCID))
			Expect(len(cids[0].Transactions)).To(Equal(4))
			Expect(eth.TxModelsContainsCID(cids[0].Transactions, test_helpers.MockCIDWrapper.Transactions[0].CID)).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cids[0].Transactions, test_helpers.MockCIDWrapper.Transactions[1].CID)).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cids[0].Transactions, test_helpers.MockCIDWrapper.Transactions[2].CID)).To(BeTrue())
			Expect(len(cids[0].Receipts)).To(Equal(4))
			Expect(eth.ReceiptModelsContainsCID(cids[0].Receipts, expectedRctCIDsAndLeafNodes[0].LeafCID)).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cids[0].Receipts, expectedRctCIDsAndLeafNodes[1].LeafCID)).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cids[0].Receipts, expectedRctCIDsAndLeafNodes[2].LeafCID)).To(BeTrue())
			Expect(len(cids[0].StateNodes)).To(Equal(2))

			for _, stateNode := range cids[0].StateNodes {
				if stateNode.CID == test_helpers.State1CID.String() {
					Expect(stateNode.StateKey).To(Equal(common.BytesToHash(test_helpers.ContractLeafKey).Hex()))
					Expect(stateNode.NodeType).To(Equal(2))
					Expect(stateNode.Path).To(Equal([]byte{'\x06'}))
				}
				if stateNode.CID == test_helpers.State2CID.String() {
					Expect(stateNode.StateKey).To(Equal(common.BytesToHash(test_helpers.AccountLeafKey).Hex()))
					Expect(stateNode.NodeType).To(Equal(2))
					Expect(stateNode.Path).To(Equal([]byte{'\x0c'}))
				}
			}
			Expect(len(cids[0].StorageNodes)).To(Equal(1))
			expectedStorageNodeCIDs := test_helpers.MockCIDWrapper.StorageNodes
			expectedStorageNodeCIDs[0].HeaderID = cids[0].StorageNodes[0].HeaderID
			expectedStorageNodeCIDs[0].StatePath = cids[0].StorageNodes[0].StatePath
			Expect(cids[0].StorageNodes).To(Equal(expectedStorageNodeCIDs))
		})

		It("Applies filters from the provided config.Subscription", func() {
			type rctCIDAndMHKeyResult struct {
				LeafCID   string `db:"leaf_cid"`
				LeafMhKey string `db:"leaf_mh_key"`
			}
			expectedRctCIDsAndLeafNodes := make([]rctCIDAndMHKeyResult, 0)
			pgStr := `SELECT receipt_cids.leaf_cid, receipt_cids.leaf_mh_key FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
				WHERE receipt_cids.tx_id = transaction_cids.tx_hash
				AND transaction_cids.header_id = header_cids.block_hash
				AND header_cids.block_number = $1
				ORDER BY transaction_cids.index`
			err := db.Select(&expectedRctCIDsAndLeafNodes, pgStr, test_helpers.BlockNumber.Uint64())
			cids1, empty, err := retriever.Retrieve(rctAddressFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids1)).To(Equal(1))
			Expect(cids1[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids1[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids1[0].Transactions)).To(Equal(0))
			Expect(len(cids1[0].StateNodes)).To(Equal(0))
			Expect(len(cids1[0].StorageNodes)).To(Equal(0))
			Expect(len(cids1[0].Receipts)).To(Equal(1))
			expectedReceiptCID := test_helpers.MockCIDWrapper.Receipts[0]
			expectedReceiptCID.TxID = cids1[0].Receipts[0].TxID
			expectedReceiptCID.LeafCID = expectedRctCIDsAndLeafNodes[0].LeafCID
			expectedReceiptCID.LeafMhKey = expectedRctCIDsAndLeafNodes[0].LeafMhKey
			Expect(cids1[0].Receipts[0]).To(Equal(expectedReceiptCID))

			cids2, empty, err := retriever.Retrieve(rctTopicsFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids2)).To(Equal(1))
			Expect(cids2[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids2[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids2[0].Transactions)).To(Equal(0))
			Expect(len(cids2[0].StateNodes)).To(Equal(0))
			Expect(len(cids2[0].StorageNodes)).To(Equal(0))
			Expect(len(cids2[0].Receipts)).To(Equal(1))
			expectedReceiptCID = test_helpers.MockCIDWrapper.Receipts[0]
			expectedReceiptCID.TxID = cids2[0].Receipts[0].TxID
			expectedReceiptCID.LeafCID = expectedRctCIDsAndLeafNodes[0].LeafCID
			expectedReceiptCID.LeafMhKey = expectedRctCIDsAndLeafNodes[0].LeafMhKey
			Expect(cids2[0].Receipts[0]).To(Equal(expectedReceiptCID))

			cids3, empty, err := retriever.Retrieve(rctTopicsAndAddressFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids3)).To(Equal(1))
			Expect(cids3[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids3[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids3[0].Transactions)).To(Equal(0))
			Expect(len(cids3[0].StateNodes)).To(Equal(0))
			Expect(len(cids3[0].StorageNodes)).To(Equal(0))
			Expect(len(cids3[0].Receipts)).To(Equal(1))
			expectedReceiptCID = test_helpers.MockCIDWrapper.Receipts[0]
			expectedReceiptCID.TxID = cids3[0].Receipts[0].TxID
			expectedReceiptCID.LeafCID = expectedRctCIDsAndLeafNodes[0].LeafCID
			expectedReceiptCID.LeafMhKey = expectedRctCIDsAndLeafNodes[0].LeafMhKey
			Expect(cids3[0].Receipts[0]).To(Equal(expectedReceiptCID))

			cids4, empty, err := retriever.Retrieve(rctAddressesAndTopicFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids4)).To(Equal(1))
			Expect(cids4[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids4[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids4[0].Transactions)).To(Equal(0))
			Expect(len(cids4[0].StateNodes)).To(Equal(0))
			Expect(len(cids4[0].StorageNodes)).To(Equal(0))
			Expect(len(cids4[0].Receipts)).To(Equal(1))
			expectedReceiptCID = test_helpers.MockCIDWrapper.Receipts[1]
			expectedReceiptCID.TxID = cids4[0].Receipts[0].TxID
			expectedReceiptCID.LeafCID = expectedRctCIDsAndLeafNodes[1].LeafCID
			expectedReceiptCID.LeafMhKey = expectedRctCIDsAndLeafNodes[1].LeafMhKey
			Expect(cids4[0].Receipts[0]).To(Equal(expectedReceiptCID))

			cids5, empty, err := retriever.Retrieve(rctsForAllCollectedTrxs, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids5)).To(Equal(1))
			Expect(cids5[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids5[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids5[0].Transactions)).To(Equal(4))
			Expect(eth.TxModelsContainsCID(cids5[0].Transactions, test_helpers.Trx1CID.String())).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cids5[0].Transactions, test_helpers.Trx2CID.String())).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cids5[0].Transactions, test_helpers.Trx3CID.String())).To(BeTrue())
			Expect(len(cids5[0].StateNodes)).To(Equal(0))
			Expect(len(cids5[0].StorageNodes)).To(Equal(0))
			Expect(len(cids5[0].Receipts)).To(Equal(4))
			Expect(eth.ReceiptModelsContainsCID(cids5[0].Receipts, expectedRctCIDsAndLeafNodes[0].LeafCID)).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cids5[0].Receipts, expectedRctCIDsAndLeafNodes[1].LeafCID)).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cids5[0].Receipts, expectedRctCIDsAndLeafNodes[2].LeafCID)).To(BeTrue())

			cids6, empty, err := retriever.Retrieve(rctsForSelectCollectedTrxs, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids6)).To(Equal(1))
			Expect(cids6[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids6[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids6[0].Transactions)).To(Equal(1))
			expectedTxCID := test_helpers.MockCIDWrapper.Transactions[1]
			expectedTxCID.TxHash = cids6[0].Transactions[0].TxHash
			expectedTxCID.HeaderID = cids6[0].Transactions[0].HeaderID
			Expect(cids6[0].Transactions[0]).To(Equal(expectedTxCID))
			Expect(len(cids6[0].StateNodes)).To(Equal(0))
			Expect(len(cids6[0].StorageNodes)).To(Equal(0))
			Expect(len(cids6[0].Receipts)).To(Equal(1))
			expectedReceiptCID = test_helpers.MockCIDWrapper.Receipts[1]
			expectedReceiptCID.TxID = cids6[0].Receipts[0].TxID
			expectedReceiptCID.LeafCID = expectedRctCIDsAndLeafNodes[1].LeafCID
			expectedReceiptCID.LeafMhKey = expectedRctCIDsAndLeafNodes[1].LeafMhKey
			Expect(cids6[0].Receipts[0]).To(Equal(expectedReceiptCID))

			cids7, empty, err := retriever.Retrieve(stateFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids7)).To(Equal(1))
			Expect(cids7[0].BlockNumber).To(Equal(test_helpers.MockCIDWrapper.BlockNumber))
			Expect(cids7[0].Header).To(Equal(models.HeaderModel{}))
			Expect(len(cids7[0].Transactions)).To(Equal(0))
			Expect(len(cids7[0].Receipts)).To(Equal(0))
			Expect(len(cids7[0].StorageNodes)).To(Equal(0))
			Expect(len(cids7[0].StateNodes)).To(Equal(1))
			Expect(cids7[0].StateNodes[0]).To(Equal(models.StateNodeModel{
				BlockNumber: "1",
				HeaderID:    cids7[0].StateNodes[0].HeaderID,
				NodeType:    2,
				StateKey:    common.BytesToHash(test_helpers.AccountLeafKey).Hex(),
				CID:         test_helpers.State2CID.String(),
				MhKey:       test_helpers.State2MhKey,
				Path:        []byte{'\x0c'},
			}))

			_, empty, err = retriever.Retrieve(rctTopicsAndAddressFilterFail, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).To(BeTrue())
		})
	})

	Describe("RetrieveFirstBlockNumber", func() {
		It("Throws an error if there are no blocks in the database", func() {
			_, err := retriever.RetrieveFirstBlockNumber()
			Expect(err).To(HaveOccurred())
		})
		It("Gets the number of the first block that has data in the database", func() {
			tx, err := diffIndexer.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
			Expect(err).ToNot(HaveOccurred())

			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			num, err := retriever.RetrieveFirstBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1)))
		})

		It("Gets the number of the first block that has data in the database", func() {
			payload := test_helpers.MockConvertedPayload
			payload.Block = newMockBlock(1010101)
			tx, err := diffIndexer.PushBlock(payload.Block, payload.Receipts, payload.Block.Difficulty())
			Expect(err).ToNot(HaveOccurred())

			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			num, err := retriever.RetrieveFirstBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1010101)))
		})

		It("Gets the number of the first block that has data in the database", func() {
			payload1 := test_helpers.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := payload1
			payload2.Block = newMockBlock(5)
			tx, err := diffIndexer.PushBlock(payload1.Block, payload1.Receipts, payload1.Block.Difficulty())
			Expect(err).ToNot(HaveOccurred())
			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			tx, err = diffIndexer.PushBlock(payload2.Block, payload2.Receipts, payload2.Block.Difficulty())
			Expect(err).ToNot(HaveOccurred())
			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			num, err := retriever.RetrieveFirstBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(5)))
		})
	})

	Describe("RetrieveLastBlockNumber", func() {
		It("Throws an error if there are no blocks in the database", func() {
			_, err := retriever.RetrieveLastBlockNumber()
			Expect(err).To(HaveOccurred())
		})
		It("Gets the number of the latest block that has data in the database", func() {
			tx, err := diffIndexer.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
			Expect(err).ToNot(HaveOccurred())
			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			num, err := retriever.RetrieveLastBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1)))
		})

		It("Gets the number of the latest block that has data in the database", func() {
			payload := test_helpers.MockConvertedPayload
			payload.Block = newMockBlock(1010101)
			tx, err := diffIndexer.PushBlock(payload.Block, payload.Receipts, payload.Block.Difficulty())
			Expect(err).ToNot(HaveOccurred())

			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			num, err := retriever.RetrieveLastBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1010101)))
		})

		It("Gets the number of the latest block that has data in the database", func() {
			payload1 := test_helpers.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := payload1
			payload2.Block = newMockBlock(5)
			tx, err := diffIndexer.PushBlock(payload1.Block, payload1.Receipts, payload1.Block.Difficulty())
			Expect(err).ToNot(HaveOccurred())
			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			tx, err = diffIndexer.PushBlock(payload2.Block, payload2.Receipts, payload2.Block.Difficulty())
			Expect(err).ToNot(HaveOccurred())
			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())

			num, err := retriever.RetrieveLastBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1010101)))
		})
	})
})

func newMockBlock(blockNumber uint64) *types.Block {
	header := test_helpers.MockHeader
	header.Number.SetUint64(blockNumber)
	return types.NewBlock(&test_helpers.MockHeader, test_helpers.MockTransactions, nil, test_helpers.MockReceipts, new(trie.Trie))
}
