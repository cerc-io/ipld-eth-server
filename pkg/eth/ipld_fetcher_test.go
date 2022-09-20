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
	"github.com/ethereum/go-ethereum/statediff/indexer/interfaces"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth/test_helpers"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/shared"
)

var _ = Describe("IPLDFetcher", func() {
	var (
		db            *sqlx.DB
		pubAndIndexer interfaces.StateDiffIndexer
		fetcher       *eth.IPLDFetcher
	)
	Describe("Fetch", func() {
		BeforeEach(func() {
			var (
				err error
				tx  interfaces.Batch
			)
			db = shared.SetupDB()
			pubAndIndexer = shared.SetupTestStateDiffIndexer(ctx, params.TestChainConfig, test_helpers.Genesis.Hash())

			tx, err = pubAndIndexer.PushBlock(test_helpers.MockBlock, test_helpers.MockReceipts, test_helpers.MockBlock.Difficulty())
			for _, node := range test_helpers.MockStateNodes {
				err = pubAndIndexer.PushStateNode(tx, node, test_helpers.MockBlock.Hash().String())
				Expect(err).ToNot(HaveOccurred())
			}

			err = tx.Submit(err)
			Expect(err).ToNot(HaveOccurred())
			fetcher = eth.NewIPLDFetcher(db)

		})
		AfterEach(func() {
			shared.TearDownDB(db)
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
