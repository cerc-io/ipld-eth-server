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

/*
import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/mocks"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var _ = Describe("IPLD Retriever", func() {
	var (
		db   *postgres.DB
		repo *eth2.IPLDPublisher
		//retriever *eth.IPLDRetriever
	)
	BeforeEach(func() {
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		repo = eth2.NewIPLDPublisher(db)
		//retriever = eth.NewIPLDRetriever(db)
		err = repo.Publish(mocks.MockConvertedPayload)
		Expect(err).ToNot(HaveOccurred())
		err = repo.Publish(mocks.MockConvertedPayload2)
		Expect(err).ToNot(HaveOccurred())
	})
	AfterEach(func() {
		eth.TearDownDB(db)
	})

	Describe("RetrieveHeadersByHashes", func() {
		It("Retrieves all of the headers that correspond to the provided hashes", func() {

		})
	})

	Describe("RetrieveHeadersByBlockNumber", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveHeaderByHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveUnclesByHashes", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveUnclesByBlockHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveUnclesByBlockNumber", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveUncleByHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveTransactionsByHashes", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveTransactionsByBlockHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveTransactionsByBlockNumber", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveTransactionByTxHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveReceiptsByTxHashes", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveReceiptsByBlockHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveReceiptsByBlockNumber", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveReceiptByHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveAccountByAddressAndBlockHash", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

	Describe("RetrieveAccountByAddressAndBlockNumber", func() {
		It("Retrieves all CIDs for the given blocknumber when provided an open filter", func() {

		})
	})

})
*/
