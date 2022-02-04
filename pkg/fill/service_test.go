// VulcanizeDB
// Copyright © 2022 Vulcanize

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

package fill_test

import (
	"math/big"

	"github.com/ethereum/go-ethereum/statediff/indexer/postgres"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ethereum/go-ethereum/statediff/indexer"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"

	fill "github.com/vulcanize/ipld-eth-server/pkg/fill"
	"github.com/vulcanize/ipld-eth-server/pkg/serve"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var _ = Describe("Service", func() {

	var (
		db                      *postgres.DB
		watchedAddressGapFiller *fill.Service
		statediffIndexer        *indexer.StateDiffIndexer
		err                     error

		contract1Address = "0x5d663F5269090bD2A7DC2390c911dF6083D7b28F"
		contract2Address = "0x6Eb7e5C66DB8af2E96159AC440cbc8CDB7fbD26B"
		contract3Address = "0xcfeB164C328CA13EFd3C77E1980d94975aDfedfc"
	)

	It("test init", func() {
		// db initialization
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())

		// indexer initialization
		statediffIndexer, err = indexer.NewStateDiffIndexer(nil, db)
		Expect(err).ToNot(HaveOccurred())

		// fill service intialization
		watchedAddressGapFiller = fill.New(&serve.Config{
			DB: db,
		})
	})

	defer It("test teardown", func() {
		shared.TearDownDB(db)
	})

	Describe("GetFillAddresses", func() {
		Context("overlapping fill ranges", func() {
			It("gives the range to run fill for each address", func() {
				// input data
				rows := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
					},
					{
						Address:      contract2Address,
						CreatedAt:    40,
						WatchedAt:    70,
						LastFilledAt: 0,
					},
					{
						Address:      contract3Address,
						CreatedAt:    20,
						WatchedAt:    30,
						LastFilledAt: 0,
					},
				}

				// expected output data
				expectedOutputAddresses := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
						StartBlock:   10,
						EndBlock:     50,
					},
					{
						Address:      contract2Address,
						CreatedAt:    40,
						WatchedAt:    70,
						LastFilledAt: 0,
						StartBlock:   40,
						EndBlock:     70,
					},
					{
						Address:      contract3Address,
						CreatedAt:    20,
						WatchedAt:    30,
						LastFilledAt: 0,
						StartBlock:   20,
						EndBlock:     30,
					},
				}
				expectedOutputStartBlock := uint64(10)
				expectedOutputEndBlock := uint64(70)

				fillWatchedAddresses, minStartBlock, maxEndBlock := watchedAddressGapFiller.GetFillAddresses(rows)

				Expect(fillWatchedAddresses).To(Equal(expectedOutputAddresses))
				Expect(minStartBlock).To(Equal(expectedOutputStartBlock))
				Expect(maxEndBlock).To(Equal(expectedOutputEndBlock))
			})
		})

		Context("non-overlapping fill ranges", func() {
			It("gives the range to run fill for each address", func() {
				// input data
				rows := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
					},
					{
						Address:      contract2Address,
						CreatedAt:    70,
						WatchedAt:    90,
						LastFilledAt: 0,
					},
				}

				// expected output data
				expectedOutputAddresses := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
						StartBlock:   10,
						EndBlock:     50,
					},
					{
						Address:      contract2Address,
						CreatedAt:    70,
						WatchedAt:    90,
						LastFilledAt: 0,
						StartBlock:   70,
						EndBlock:     90,
					},
				}
				expectedOutputStartBlock := uint64(10)
				expectedOutputEndBlock := uint64(90)

				fillWatchedAddresses, minStartBlock, maxEndBlock := watchedAddressGapFiller.GetFillAddresses(rows)

				Expect(fillWatchedAddresses).To(Equal(expectedOutputAddresses))
				Expect(minStartBlock).To(Equal(expectedOutputStartBlock))
				Expect(maxEndBlock).To(Equal(expectedOutputEndBlock))
			})
		})

		Context("a contract watched before it was created", func() {
			It("gives no range for an address when it is watched before it's created", func() {
				// input data
				rows := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
					},
					{
						Address:      contract2Address,
						CreatedAt:    90,
						WatchedAt:    70,
						LastFilledAt: 0,
					},
				}

				// expected output data
				expectedOutputAddresses := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
						StartBlock:   10,
						EndBlock:     50,
					},
				}
				expectedOutputStartBlock := uint64(10)
				expectedOutputEndBlock := uint64(50)

				fillWatchedAddresses, minStartBlock, maxEndBlock := watchedAddressGapFiller.GetFillAddresses(rows)

				Expect(fillWatchedAddresses).To(Equal(expectedOutputAddresses))
				Expect(minStartBlock).To(Equal(expectedOutputStartBlock))
				Expect(maxEndBlock).To(Equal(expectedOutputEndBlock))
			})
		})

		Context("a contract having some of the gap filled earlier", func() {
			It("gives the remaining range for an address to run fill for", func() {
				// input data
				rows := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
					},
					{
						Address:      contract2Address,
						CreatedAt:    40,
						WatchedAt:    70,
						LastFilledAt: 50,
					},
				}

				// expected output data
				expectedOutputAddresses := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
						StartBlock:   10,
						EndBlock:     50,
					},
					{
						Address:      contract2Address,
						CreatedAt:    40,
						WatchedAt:    70,
						LastFilledAt: 50,
						StartBlock:   51,
						EndBlock:     70,
					},
				}
				expectedOutputStartBlock := uint64(10)
				expectedOutputEndBlock := uint64(70)

				fillWatchedAddresses, minStartBlock, maxEndBlock := watchedAddressGapFiller.GetFillAddresses(rows)

				Expect(fillWatchedAddresses).To(Equal(expectedOutputAddresses))
				Expect(minStartBlock).To(Equal(expectedOutputStartBlock))
				Expect(maxEndBlock).To(Equal(expectedOutputEndBlock))
			})

			It("gives no range for an address when the gap is already filled", func() {
				// input data
				rows := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
					},
					{
						Address:      contract2Address,
						CreatedAt:    40,
						WatchedAt:    70,
						LastFilledAt: 70,
					},
				}

				// expected output data
				expectedOutputAddresses := []fill.WatchedAddress{
					{
						Address:      contract1Address,
						CreatedAt:    10,
						WatchedAt:    50,
						LastFilledAt: 0,
						StartBlock:   10,
						EndBlock:     50,
					},
				}
				expectedOutputStartBlock := uint64(10)
				expectedOutputEndBlock := uint64(50)

				fillWatchedAddresses, minStartBlock, maxEndBlock := watchedAddressGapFiller.GetFillAddresses(rows)

				Expect(fillWatchedAddresses).To(Equal(expectedOutputAddresses))
				Expect(minStartBlock).To(Equal(expectedOutputStartBlock))
				Expect(maxEndBlock).To(Equal(expectedOutputEndBlock))
			})
		})
	})

	Describe("UpdateLastFilledAt", func() {
		pgStr := "SELECT * FROM eth_meta.watched_addresses"

		BeforeEach(func() {
			shared.TearDownDB(db)
		})

		It("updates last filled at for a single address", func() {
			// fill db with watched addresses
			watchedAddresses := []sdtypes.WatchAddressArg{
				{
					Address:   contract1Address,
					CreatedAt: 10,
				},
			}
			watchedAt := uint64(50)
			err = statediffIndexer.InsertWatchedAddresses(watchedAddresses, big.NewInt(int64(watchedAt)))
			Expect(err).ToNot(HaveOccurred())

			// update last filled at block in the db
			fillAddresses := []interface{}{
				contract1Address,
			}
			fillAt := uint64(12)
			watchedAddressGapFiller.UpdateLastFilledAt(fillAt, fillAddresses)

			// expected data
			expectedData := []fill.WatchedAddress{
				{
					Address:      contract1Address,
					CreatedAt:    10,
					WatchedAt:    watchedAt,
					LastFilledAt: fillAt,
				},
			}

			rows := []fill.WatchedAddress{}
			err = db.Select(&rows, pgStr)
			Expect(err).ToNot(HaveOccurred())

			Expect(rows).To(Equal(expectedData))
		})

		It("updates last filled at for multiple address", func() {
			// fill db with watched addresses
			watchedAddresses := []sdtypes.WatchAddressArg{
				{
					Address:   contract1Address,
					CreatedAt: 10,
				},
				{
					Address:   contract2Address,
					CreatedAt: 20,
				},
				{
					Address:   contract3Address,
					CreatedAt: 30,
				},
			}
			watchedAt := uint64(50)
			err = statediffIndexer.InsertWatchedAddresses(watchedAddresses, big.NewInt(int64(watchedAt)))
			Expect(err).ToNot(HaveOccurred())

			// update last filled at block in the db
			fillAddresses := []interface{}{
				contract1Address,
				contract2Address,
				contract3Address,
			}
			fillAt := uint64(50)
			watchedAddressGapFiller.UpdateLastFilledAt(fillAt, fillAddresses)

			// expected data
			expectedData := []fill.WatchedAddress{
				{
					Address:      contract1Address,
					CreatedAt:    10,
					WatchedAt:    watchedAt,
					LastFilledAt: fillAt,
				},
				{
					Address:      contract2Address,
					CreatedAt:    20,
					WatchedAt:    watchedAt,
					LastFilledAt: fillAt,
				},
				{
					Address:      contract3Address,
					CreatedAt:    30,
					WatchedAt:    watchedAt,
					LastFilledAt: fillAt,
				},
			}

			rows := []fill.WatchedAddress{}
			err = db.Select(&rows, pgStr)
			Expect(err).ToNot(HaveOccurred())

			Expect(rows).To(Equal(expectedData))
		})
	})
})
