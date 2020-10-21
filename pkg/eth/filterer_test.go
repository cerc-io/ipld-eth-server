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
	"bytes"

	"github.com/ethereum/go-ethereum/statediff"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/vulcanize/ipld-eth-indexer/pkg/ipfs"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var (
	filterer *eth.ResponseFilterer
)

var _ = Describe("Filterer", func() {
	Describe("FilterResponse", func() {
		BeforeEach(func() {
			filterer = eth.NewResponseFilterer()
		})

		It("Transcribes all the data from the IPLDPayload into the StreamPayload if given an open filter", func() {
			iplds, err := filterer.Filter(openFilter, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds).ToNot(BeNil())
			Expect(iplds.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds.Header).To(Equal(test_helpers.MockIPLDs.Header))
			var expectedEmptyUncles []ipfs.BlockModel
			Expect(iplds.Uncles).To(Equal(expectedEmptyUncles))
			Expect(len(iplds.Transactions)).To(Equal(3))
			Expect(shared.IPLDsContainBytes(iplds.Transactions, test_helpers.MockTransactions.GetRlp(0))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds.Transactions, test_helpers.MockTransactions.GetRlp(1))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds.Transactions, test_helpers.MockTransactions.GetRlp(2))).To(BeTrue())
			Expect(len(iplds.Receipts)).To(Equal(3))
			Expect(shared.IPLDsContainBytes(iplds.Receipts, test_helpers.MockReceipts.GetRlp(0))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds.Receipts, test_helpers.MockReceipts.GetRlp(1))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds.Receipts, test_helpers.MockReceipts.GetRlp(2))).To(BeTrue())
			Expect(len(iplds.StateNodes)).To(Equal(2))
			for _, stateNode := range iplds.StateNodes {
				Expect(stateNode.Type).To(Equal(statediff.Leaf))
				if bytes.Equal(stateNode.StateLeafKey.Bytes(), test_helpers.AccountLeafKey) {
					Expect(stateNode.IPLD).To(Equal(ipfs.BlockModel{
						Data: test_helpers.State2IPLD.RawData(),
						CID:  test_helpers.State2IPLD.Cid().String(),
					}))
				}
				if bytes.Equal(stateNode.StateLeafKey.Bytes(), test_helpers.ContractLeafKey) {
					Expect(stateNode.IPLD).To(Equal(ipfs.BlockModel{
						Data: test_helpers.State1IPLD.RawData(),
						CID:  test_helpers.State1IPLD.Cid().String(),
					}))
				}
			}
			Expect(iplds.StorageNodes).To(Equal(test_helpers.MockIPLDs.StorageNodes))
		})

		It("Applies filters from the provided config.Subscription", func() {
			iplds1, err := filterer.Filter(rctAddressFilter, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds1).ToNot(BeNil())
			Expect(iplds1.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds1.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds1.Uncles)).To(Equal(0))
			Expect(len(iplds1.Transactions)).To(Equal(0))
			Expect(len(iplds1.StorageNodes)).To(Equal(0))
			Expect(len(iplds1.StateNodes)).To(Equal(0))
			Expect(len(iplds1.Receipts)).To(Equal(1))
			Expect(iplds1.Receipts[0]).To(Equal(ipfs.BlockModel{
				Data: test_helpers.Rct1IPLD.RawData(),
				CID:  test_helpers.Rct1IPLD.Cid().String(),
			}))

			iplds2, err := filterer.Filter(rctTopicsFilter, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds2).ToNot(BeNil())
			Expect(iplds2.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds2.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds2.Uncles)).To(Equal(0))
			Expect(len(iplds2.Transactions)).To(Equal(0))
			Expect(len(iplds2.StorageNodes)).To(Equal(0))
			Expect(len(iplds2.StateNodes)).To(Equal(0))
			Expect(len(iplds2.Receipts)).To(Equal(1))
			Expect(iplds2.Receipts[0]).To(Equal(ipfs.BlockModel{
				Data: test_helpers.Rct1IPLD.RawData(),
				CID:  test_helpers.Rct1IPLD.Cid().String(),
			}))

			iplds3, err := filterer.Filter(rctTopicsAndAddressFilter, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds3).ToNot(BeNil())
			Expect(iplds3.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds3.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds3.Uncles)).To(Equal(0))
			Expect(len(iplds3.Transactions)).To(Equal(0))
			Expect(len(iplds3.StorageNodes)).To(Equal(0))
			Expect(len(iplds3.StateNodes)).To(Equal(0))
			Expect(len(iplds3.Receipts)).To(Equal(1))
			Expect(iplds3.Receipts[0]).To(Equal(ipfs.BlockModel{
				Data: test_helpers.Rct1IPLD.RawData(),
				CID:  test_helpers.Rct1IPLD.Cid().String(),
			}))

			iplds4, err := filterer.Filter(rctAddressesAndTopicFilter, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds4).ToNot(BeNil())
			Expect(iplds4.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds4.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds4.Uncles)).To(Equal(0))
			Expect(len(iplds4.Transactions)).To(Equal(0))
			Expect(len(iplds4.StorageNodes)).To(Equal(0))
			Expect(len(iplds4.StateNodes)).To(Equal(0))
			Expect(len(iplds4.Receipts)).To(Equal(1))
			Expect(iplds4.Receipts[0]).To(Equal(ipfs.BlockModel{
				Data: test_helpers.Rct2IPLD.RawData(),
				CID:  test_helpers.Rct2IPLD.Cid().String(),
			}))

			iplds5, err := filterer.Filter(rctsForAllCollectedTrxs, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds5).ToNot(BeNil())
			Expect(iplds5.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds5.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds5.Uncles)).To(Equal(0))
			Expect(len(iplds5.Transactions)).To(Equal(3))
			Expect(shared.IPLDsContainBytes(iplds5.Transactions, test_helpers.MockTransactions.GetRlp(0))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds5.Transactions, test_helpers.MockTransactions.GetRlp(1))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds5.Transactions, test_helpers.MockTransactions.GetRlp(2))).To(BeTrue())
			Expect(len(iplds5.StorageNodes)).To(Equal(0))
			Expect(len(iplds5.StateNodes)).To(Equal(0))
			Expect(len(iplds5.Receipts)).To(Equal(3))
			Expect(shared.IPLDsContainBytes(iplds5.Receipts, test_helpers.MockReceipts.GetRlp(0))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds5.Receipts, test_helpers.MockReceipts.GetRlp(1))).To(BeTrue())
			Expect(shared.IPLDsContainBytes(iplds5.Receipts, test_helpers.MockReceipts.GetRlp(2))).To(BeTrue())

			iplds6, err := filterer.Filter(rctsForSelectCollectedTrxs, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds6).ToNot(BeNil())
			Expect(iplds6.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds6.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds6.Uncles)).To(Equal(0))
			Expect(len(iplds6.Transactions)).To(Equal(1))
			Expect(shared.IPLDsContainBytes(iplds5.Transactions, test_helpers.MockTransactions.GetRlp(1))).To(BeTrue())
			Expect(len(iplds6.StorageNodes)).To(Equal(0))
			Expect(len(iplds6.StateNodes)).To(Equal(0))
			Expect(len(iplds6.Receipts)).To(Equal(1))
			Expect(iplds4.Receipts[0]).To(Equal(ipfs.BlockModel{
				Data: test_helpers.Rct2IPLD.RawData(),
				CID:  test_helpers.Rct2IPLD.Cid().String(),
			}))

			iplds7, err := filterer.Filter(stateFilter, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds7).ToNot(BeNil())
			Expect(iplds7.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds7.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds7.Uncles)).To(Equal(0))
			Expect(len(iplds7.Transactions)).To(Equal(0))
			Expect(len(iplds7.StorageNodes)).To(Equal(0))
			Expect(len(iplds7.Receipts)).To(Equal(0))
			Expect(len(iplds7.StateNodes)).To(Equal(1))
			Expect(iplds7.StateNodes[0].StateLeafKey.Bytes()).To(Equal(test_helpers.AccountLeafKey))
			Expect(iplds7.StateNodes[0].IPLD).To(Equal(ipfs.BlockModel{
				Data: test_helpers.State2IPLD.RawData(),
				CID:  test_helpers.State2IPLD.Cid().String(),
			}))

			iplds8, err := filterer.Filter(rctTopicsAndAddressFilterFail, test_helpers.MockConvertedPayload)
			Expect(err).ToNot(HaveOccurred())
			Expect(iplds8).ToNot(BeNil())
			Expect(iplds8.BlockNumber.Int64()).To(Equal(test_helpers.MockIPLDs.BlockNumber.Int64()))
			Expect(iplds8.Header).To(Equal(ipfs.BlockModel{}))
			Expect(len(iplds8.Uncles)).To(Equal(0))
			Expect(len(iplds8.Transactions)).To(Equal(0))
			Expect(len(iplds8.StorageNodes)).To(Equal(0))
			Expect(len(iplds8.StateNodes)).To(Equal(0))
			Expect(len(iplds8.Receipts)).To(Equal(0))
		})
	})
})
