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

package eth

import (
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	. "github.com/onsi/gomega"
)

// TxModelsContainsCID used to check if a list of TxModels contains a specific cid string
func TxModelsContainsCID(txs []models.TxModel, cid string) bool {
	for _, tx := range txs {
		if tx.CID == cid {
			return true
		}
	}
	return false
}

// ReceiptModelsContainsCID used to check if a list of ReceiptModel contains a specific cid string
func ReceiptModelsContainsCID(rcts []models.ReceiptModel, cid string) bool {
	for _, rct := range rcts {
		if rct.LeafCID == cid {
			return true
		}
	}
	return false
}

func CheckGetSliceResponse(sliceResponse GetSliceResponse, expectedResponse GetSliceResponse) {
	Expect(sliceResponse.SliceID).To(Equal(expectedResponse.SliceID))
	Expect(sliceResponse.MetaData.NodeStats).To(Equal(expectedResponse.MetaData.NodeStats))
	Expect(sliceResponse.TrieNodes).To(Equal(expectedResponse.TrieNodes))
	Expect(sliceResponse.Leaves).To(Equal(expectedResponse.Leaves))
}
