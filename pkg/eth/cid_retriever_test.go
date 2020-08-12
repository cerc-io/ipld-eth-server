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

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth"
	eth2 "github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth/mocks"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/postgres"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/shared"
)

var (
	openFilter = &eth.SubscriptionSettings{
		Start:         big.NewInt(0),
		End:           big.NewInt(1),
		HeaderFilter:  eth.HeaderFilter{},
		TxFilter:      eth.TxFilter{},
		ReceiptFilter: eth.ReceiptFilter{},
		StateFilter:   eth.StateFilter{},
		StorageFilter: eth.StorageFilter{},
	}
	rctAddressFilter = &eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Off: true,
		},
		ReceiptFilter: eth.ReceiptFilter{
			LogAddresses: []string{mocks.Address.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctTopicsFilter = &eth.SubscriptionSettings{
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
	rctTopicsAndAddressFilter = &eth.SubscriptionSettings{
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
			LogAddresses: []string{mocks.Address.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctTopicsAndAddressFilterFail = &eth.SubscriptionSettings{
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
			LogAddresses: []string{mocks.Address.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctAddressesAndTopicFilter = &eth.SubscriptionSettings{
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
			LogAddresses: []string{mocks.Address.String(), mocks.AnotherAddress.String()},
		},
		StateFilter: eth.StateFilter{
			Off: true,
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
	rctsForAllCollectedTrxs = &eth.SubscriptionSettings{
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
	rctsForSelectCollectedTrxs = &eth.SubscriptionSettings{
		Start: big.NewInt(0),
		End:   big.NewInt(1),
		HeaderFilter: eth.HeaderFilter{
			Off: true,
		},
		TxFilter: eth.TxFilter{
			Dst: []string{mocks.AnotherAddress.String()}, // We only filter for one of the trxs so we will only get the one corresponding receipt
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
	stateFilter = &eth.SubscriptionSettings{
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
			Addresses: []string{mocks.AccountAddresss.Hex()},
		},
		StorageFilter: eth.StorageFilter{
			Off: true,
		},
	}
)

var _ = Describe("Retriever", func() {
	var (
		db        *postgres.DB
		repo      *eth2.IPLDPublisher
		retriever *eth2.CIDRetriever
	)
	BeforeEach(func() {
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		repo = eth2.NewIPLDPublisher(db)
		retriever = eth2.NewCIDRetriever(db)
	})
	AfterEach(func() {
		eth.TearDownDB(db)
	})

	Describe("Retrieve", func() {
		BeforeEach(func() {
			err := repo.Publish(mocks.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
		})
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {
			cids, empty, err := retriever.Retrieve(openFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids)).To(Equal(1))
			cidWrapper, ok := cids[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			expectedHeaderCID := mocks.MockCIDWrapper.Header
			expectedHeaderCID.ID = cidWrapper.Header.ID
			expectedHeaderCID.NodeID = cidWrapper.Header.NodeID
			Expect(cidWrapper.Header).To(Equal(expectedHeaderCID))
			Expect(len(cidWrapper.Transactions)).To(Equal(3))
			Expect(eth.TxModelsContainsCID(cidWrapper.Transactions, mocks.MockCIDWrapper.Transactions[0].CID)).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cidWrapper.Transactions, mocks.MockCIDWrapper.Transactions[1].CID)).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cidWrapper.Transactions, mocks.MockCIDWrapper.Transactions[2].CID)).To(BeTrue())
			Expect(len(cidWrapper.Receipts)).To(Equal(3))
			Expect(eth.ReceiptModelsContainsCID(cidWrapper.Receipts, mocks.MockCIDWrapper.Receipts[0].CID)).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cidWrapper.Receipts, mocks.MockCIDWrapper.Receipts[1].CID)).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cidWrapper.Receipts, mocks.MockCIDWrapper.Receipts[2].CID)).To(BeTrue())
			Expect(len(cidWrapper.StateNodes)).To(Equal(2))
			for _, stateNode := range cidWrapper.StateNodes {
				if stateNode.CID == mocks.State1CID.String() {
					Expect(stateNode.StateKey).To(Equal(common.BytesToHash(mocks.ContractLeafKey).Hex()))
					Expect(stateNode.NodeType).To(Equal(2))
					Expect(stateNode.Path).To(Equal([]byte{'\x06'}))
				}
				if stateNode.CID == mocks.State2CID.String() {
					Expect(stateNode.StateKey).To(Equal(common.BytesToHash(mocks.AccountLeafKey).Hex()))
					Expect(stateNode.NodeType).To(Equal(2))
					Expect(stateNode.Path).To(Equal([]byte{'\x0c'}))
				}
			}
			Expect(len(cidWrapper.StorageNodes)).To(Equal(1))
			expectedStorageNodeCIDs := mocks.MockCIDWrapper.StorageNodes
			expectedStorageNodeCIDs[0].ID = cidWrapper.StorageNodes[0].ID
			expectedStorageNodeCIDs[0].StateID = cidWrapper.StorageNodes[0].StateID
			Expect(cidWrapper.StorageNodes).To(Equal(expectedStorageNodeCIDs))
		})

		It("Applies filters from the provided config.Subscription", func() {
			cids1, empty, err := retriever.Retrieve(rctAddressFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids1)).To(Equal(1))
			cidWrapper1, ok := cids1[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper1.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper1.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper1.Transactions)).To(Equal(0))
			Expect(len(cidWrapper1.StateNodes)).To(Equal(0))
			Expect(len(cidWrapper1.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper1.Receipts)).To(Equal(1))
			expectedReceiptCID := mocks.MockCIDWrapper.Receipts[0]
			expectedReceiptCID.ID = cidWrapper1.Receipts[0].ID
			expectedReceiptCID.TxID = cidWrapper1.Receipts[0].TxID
			Expect(cidWrapper1.Receipts[0]).To(Equal(expectedReceiptCID))

			cids2, empty, err := retriever.Retrieve(rctTopicsFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids2)).To(Equal(1))
			cidWrapper2, ok := cids2[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper2.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper2.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper2.Transactions)).To(Equal(0))
			Expect(len(cidWrapper2.StateNodes)).To(Equal(0))
			Expect(len(cidWrapper2.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper2.Receipts)).To(Equal(1))
			expectedReceiptCID = mocks.MockCIDWrapper.Receipts[0]
			expectedReceiptCID.ID = cidWrapper2.Receipts[0].ID
			expectedReceiptCID.TxID = cidWrapper2.Receipts[0].TxID
			Expect(cidWrapper2.Receipts[0]).To(Equal(expectedReceiptCID))

			cids3, empty, err := retriever.Retrieve(rctTopicsAndAddressFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids3)).To(Equal(1))
			cidWrapper3, ok := cids3[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper3.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper3.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper3.Transactions)).To(Equal(0))
			Expect(len(cidWrapper3.StateNodes)).To(Equal(0))
			Expect(len(cidWrapper3.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper3.Receipts)).To(Equal(1))
			expectedReceiptCID = mocks.MockCIDWrapper.Receipts[0]
			expectedReceiptCID.ID = cidWrapper3.Receipts[0].ID
			expectedReceiptCID.TxID = cidWrapper3.Receipts[0].TxID
			Expect(cidWrapper3.Receipts[0]).To(Equal(expectedReceiptCID))

			cids4, empty, err := retriever.Retrieve(rctAddressesAndTopicFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids4)).To(Equal(1))
			cidWrapper4, ok := cids4[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper4.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper4.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper4.Transactions)).To(Equal(0))
			Expect(len(cidWrapper4.StateNodes)).To(Equal(0))
			Expect(len(cidWrapper4.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper4.Receipts)).To(Equal(1))
			expectedReceiptCID = mocks.MockCIDWrapper.Receipts[1]
			expectedReceiptCID.ID = cidWrapper4.Receipts[0].ID
			expectedReceiptCID.TxID = cidWrapper4.Receipts[0].TxID
			Expect(cidWrapper4.Receipts[0]).To(Equal(expectedReceiptCID))

			cids5, empty, err := retriever.Retrieve(rctsForAllCollectedTrxs, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids5)).To(Equal(1))
			cidWrapper5, ok := cids5[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper5.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper5.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper5.Transactions)).To(Equal(3))
			Expect(eth.TxModelsContainsCID(cidWrapper5.Transactions, mocks.Trx1CID.String())).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cidWrapper5.Transactions, mocks.Trx2CID.String())).To(BeTrue())
			Expect(eth.TxModelsContainsCID(cidWrapper5.Transactions, mocks.Trx3CID.String())).To(BeTrue())
			Expect(len(cidWrapper5.StateNodes)).To(Equal(0))
			Expect(len(cidWrapper5.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper5.Receipts)).To(Equal(3))
			Expect(eth.ReceiptModelsContainsCID(cidWrapper5.Receipts, mocks.Rct1CID.String())).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cidWrapper5.Receipts, mocks.Rct2CID.String())).To(BeTrue())
			Expect(eth.ReceiptModelsContainsCID(cidWrapper5.Receipts, mocks.Rct3CID.String())).To(BeTrue())

			cids6, empty, err := retriever.Retrieve(rctsForSelectCollectedTrxs, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids6)).To(Equal(1))
			cidWrapper6, ok := cids6[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper6.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper6.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper6.Transactions)).To(Equal(1))
			expectedTxCID := mocks.MockCIDWrapper.Transactions[1]
			expectedTxCID.ID = cidWrapper6.Transactions[0].ID
			expectedTxCID.HeaderID = cidWrapper6.Transactions[0].HeaderID
			Expect(cidWrapper6.Transactions[0]).To(Equal(expectedTxCID))
			Expect(len(cidWrapper6.StateNodes)).To(Equal(0))
			Expect(len(cidWrapper6.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper6.Receipts)).To(Equal(1))
			expectedReceiptCID = mocks.MockCIDWrapper.Receipts[1]
			expectedReceiptCID.ID = cidWrapper6.Receipts[0].ID
			expectedReceiptCID.TxID = cidWrapper6.Receipts[0].TxID
			Expect(cidWrapper6.Receipts[0]).To(Equal(expectedReceiptCID))

			cids7, empty, err := retriever.Retrieve(stateFilter, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(empty).ToNot(BeTrue())
			Expect(len(cids7)).To(Equal(1))
			cidWrapper7, ok := cids7[0].(*eth.CIDWrapper)
			Expect(ok).To(BeTrue())
			Expect(cidWrapper7.BlockNumber).To(Equal(mocks.MockCIDWrapper.BlockNumber))
			Expect(cidWrapper7.Header).To(Equal(eth.HeaderModel{}))
			Expect(len(cidWrapper7.Transactions)).To(Equal(0))
			Expect(len(cidWrapper7.Receipts)).To(Equal(0))
			Expect(len(cidWrapper7.StorageNodes)).To(Equal(0))
			Expect(len(cidWrapper7.StateNodes)).To(Equal(1))
			Expect(cidWrapper7.StateNodes[0]).To(Equal(eth.StateNodeModel{
				ID:       cidWrapper7.StateNodes[0].ID,
				HeaderID: cidWrapper7.StateNodes[0].HeaderID,
				NodeType: 2,
				StateKey: common.BytesToHash(mocks.AccountLeafKey).Hex(),
				CID:      mocks.State2CID.String(),
				MhKey:    mocks.State2MhKey,
				Path:     []byte{'\x0c'},
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
			err := repo.Publish(mocks.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			num, err := retriever.RetrieveFirstBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1)))
		})

		It("Gets the number of the first block that has data in the database", func() {
			payload := mocks.MockConvertedPayload
			payload.Block = newMockBlock(1010101)
			err := repo.Publish(payload)
			Expect(err).ToNot(HaveOccurred())
			num, err := retriever.RetrieveFirstBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1010101)))
		})

		It("Gets the number of the first block that has data in the database", func() {
			payload1 := mocks.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := payload1
			payload2.Block = newMockBlock(5)
			err := repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload2)
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
			err := repo.Publish(mocks.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			num, err := retriever.RetrieveLastBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1)))
		})

		It("Gets the number of the latest block that has data in the database", func() {
			payload := mocks.MockConvertedPayload
			payload.Block = newMockBlock(1010101)
			err := repo.Publish(payload)
			Expect(err).ToNot(HaveOccurred())
			num, err := retriever.RetrieveLastBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1010101)))
		})

		It("Gets the number of the latest block that has data in the database", func() {
			payload1 := mocks.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := payload1
			payload2.Block = newMockBlock(5)
			err := repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload2)
			Expect(err).ToNot(HaveOccurred())
			num, err := retriever.RetrieveLastBlockNumber()
			Expect(err).ToNot(HaveOccurred())
			Expect(num).To(Equal(int64(1010101)))
		})
	})

	Describe("RetrieveGapsInData", func() {
		It("Doesn't return gaps if there are none", func() {
			payload0 := mocks.MockConvertedPayload
			payload0.Block = newMockBlock(0)
			payload1 := mocks.MockConvertedPayload
			payload2 := payload1
			payload2.Block = newMockBlock(2)
			payload3 := payload2
			payload3.Block = newMockBlock(3)
			err := repo.Publish(payload0)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload2)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload3)
			Expect(err).ToNot(HaveOccurred())
			gaps, err := retriever.RetrieveGapsInData(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(gaps)).To(Equal(0))
		})

		It("Returns the gap from 0 to the earliest block", func() {
			payload := mocks.MockConvertedPayload
			payload.Block = newMockBlock(5)
			err := repo.Publish(payload)
			Expect(err).ToNot(HaveOccurred())
			gaps, err := retriever.RetrieveGapsInData(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(gaps)).To(Equal(1))
			Expect(gaps[0].Start).To(Equal(uint64(0)))
			Expect(gaps[0].Stop).To(Equal(uint64(4)))
		})

		It("Can handle single block gaps", func() {
			payload0 := mocks.MockConvertedPayload
			payload0.Block = newMockBlock(0)
			payload1 := mocks.MockConvertedPayload
			payload3 := payload1
			payload3.Block = newMockBlock(3)
			err := repo.Publish(payload0)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload3)
			Expect(err).ToNot(HaveOccurred())
			gaps, err := retriever.RetrieveGapsInData(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(gaps)).To(Equal(1))
			Expect(gaps[0].Start).To(Equal(uint64(2)))
			Expect(gaps[0].Stop).To(Equal(uint64(2)))
		})

		It("Finds gap between two entries", func() {
			payload1 := mocks.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := payload1
			payload2.Block = newMockBlock(0)
			err := repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload2)
			Expect(err).ToNot(HaveOccurred())
			gaps, err := retriever.RetrieveGapsInData(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(gaps)).To(Equal(1))
			Expect(gaps[0].Start).To(Equal(uint64(1)))
			Expect(gaps[0].Stop).To(Equal(uint64(1010100)))
		})

		It("Finds gaps between multiple entries", func() {
			payload1 := mocks.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := mocks.MockConvertedPayload
			payload2.Block = newMockBlock(1)
			payload3 := mocks.MockConvertedPayload
			payload3.Block = newMockBlock(5)
			payload4 := mocks.MockConvertedPayload
			payload4.Block = newMockBlock(100)
			payload5 := mocks.MockConvertedPayload
			payload5.Block = newMockBlock(101)
			payload6 := mocks.MockConvertedPayload
			payload6.Block = newMockBlock(102)
			payload7 := mocks.MockConvertedPayload
			payload7.Block = newMockBlock(103)
			payload8 := mocks.MockConvertedPayload
			payload8.Block = newMockBlock(104)
			payload9 := mocks.MockConvertedPayload
			payload9.Block = newMockBlock(105)
			payload10 := mocks.MockConvertedPayload
			payload10.Block = newMockBlock(106)
			payload11 := mocks.MockConvertedPayload
			payload11.Block = newMockBlock(1000)

			err := repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload2)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload3)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload4)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload5)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload6)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload7)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload8)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload9)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload10)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload11)
			Expect(err).ToNot(HaveOccurred())

			gaps, err := retriever.RetrieveGapsInData(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(gaps)).To(Equal(5))
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 0, Stop: 0})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 2, Stop: 4})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 6, Stop: 99})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 107, Stop: 999})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 1001, Stop: 1010100})).To(BeTrue())
		})

		It("Finds validation level gaps", func() {

			payload1 := mocks.MockConvertedPayload
			payload1.Block = newMockBlock(1010101)
			payload2 := mocks.MockConvertedPayload
			payload2.Block = newMockBlock(1)
			payload3 := mocks.MockConvertedPayload
			payload3.Block = newMockBlock(5)
			payload4 := mocks.MockConvertedPayload
			payload4.Block = newMockBlock(100)
			payload5 := mocks.MockConvertedPayload
			payload5.Block = newMockBlock(101)
			payload6 := mocks.MockConvertedPayload
			payload6.Block = newMockBlock(102)
			payload7 := mocks.MockConvertedPayload
			payload7.Block = newMockBlock(103)
			payload8 := mocks.MockConvertedPayload
			payload8.Block = newMockBlock(104)
			payload9 := mocks.MockConvertedPayload
			payload9.Block = newMockBlock(105)
			payload10 := mocks.MockConvertedPayload
			payload10.Block = newMockBlock(106)
			payload11 := mocks.MockConvertedPayload
			payload11.Block = newMockBlock(107)
			payload12 := mocks.MockConvertedPayload
			payload12.Block = newMockBlock(108)
			payload13 := mocks.MockConvertedPayload
			payload13.Block = newMockBlock(109)
			payload14 := mocks.MockConvertedPayload
			payload14.Block = newMockBlock(1000)

			err := repo.Publish(payload1)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload2)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload3)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload4)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload5)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload6)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload7)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload8)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload9)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload10)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload11)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload12)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload13)
			Expect(err).ToNot(HaveOccurred())
			err = repo.Publish(payload14)
			Expect(err).ToNot(HaveOccurred())

			cleaner := eth.NewCleaner(db)
			err = cleaner.ResetValidation([][2]uint64{{101, 102}, {104, 104}, {106, 108}})
			Expect(err).ToNot(HaveOccurred())

			gaps, err := retriever.RetrieveGapsInData(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(gaps)).To(Equal(8))
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 0, Stop: 0})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 2, Stop: 4})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 6, Stop: 99})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 101, Stop: 102})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 104, Stop: 104})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 106, Stop: 108})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 110, Stop: 999})).To(BeTrue())
			Expect(shared.ListContainsGap(gaps, shared.Gap{Start: 1001, Stop: 1010100})).To(BeTrue())
		})
	})
})

func newMockBlock(blockNumber uint64) *types.Block {
	header := mocks.MockHeader
	header.Number.SetUint64(blockNumber)
	return types.NewBlock(&mocks.MockHeader, mocks.MockTransactions, nil, mocks.MockReceipts)
}
