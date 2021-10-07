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
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/statediff/indexer"
	"github.com/ethereum/go-ethereum/statediff/indexer/postgres"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
)

var _ = Describe("IPLDFetcher", func() {
	var (
		db            *postgres.DB
		pubAndIndexer *indexer.StateDiffIndexer
		fetcher       *eth.IPLDFetcher
	)
	Describe("Fetch", func() {
		BeforeEach(func() {
			var (
				err error
				tx  *indexer.BlockTx
			)
			db, err = SetupDB()
			Expect(err).ToNot(HaveOccurred())
			pubAndIndexer, err = indexer.NewStateDiffIndexer(params.TestChainConfig, db)
			Expect(err).ToNot(HaveOccurred())

			tx, err = pubAndIndexer.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
			for _, node := range test_helpers.MockStateNodes {
				err = pubAndIndexer.PushStateNode(tx, node)
				Expect(err).ToNot(HaveOccurred())
			}

			err = tx.Close(err)
			Expect(err).ToNot(HaveOccurred())
			fetcher = eth.NewIPLDFetcher(db)

		})
		AfterEach(func() {
			eth.TearDownDB(db)
		})

		It("Fetches and returns IPLDs for the CIDs provided in the CIDWrapper", func() {
			iplds, err := fetcher.Fetch(*test_helpers.MockCIDWrapper)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds).ToNot(BeNil())
			Expect(iplds.TotalDifficulty).To(Equal(test_helpers.MockConvertedPayload.TotalDifficulty))
			Expect(iplds.BlockNumber).To(Equal(test_helpers.MockConvertedPayload.Block.Number()))
			Expect(iplds.Header).To(Equal(test_helpers.MockIPLDs.Header))
			Expect(len(iplds.Uncles)).To(Equal(0))
			Expect(iplds.Transactions).To(Equal(test_helpers.MockIPLDs.Transactions))
			Expect(iplds.Receipts).To(Equal(test_helpers.MockIPLDs.Receipts))
			Expect(iplds.StateNodes).To(Equal(test_helpers.MockIPLDs.StateNodes))
			Expect(iplds.StorageNodes).To(Equal(test_helpers.MockIPLDs.StorageNodes))
		})
	})
})
