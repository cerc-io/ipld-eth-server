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

// ReceiptFilter contains filter settings for receipts
type ReceiptFilter struct {
	Off bool
	// TODO: change this so that we filter for receipts first and we always return the corresponding transaction
	MatchTxs     bool     // turn on to retrieve receipts that pair with retrieved transactions
	LogAddresses []string // receipt contains logs from the provided addresses
	Topics       [][]string
}
