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
	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth/test_helpers"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/shared"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/statediff/indexer/interfaces"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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
