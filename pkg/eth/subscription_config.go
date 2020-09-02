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
	"math/big"

	"github.com/spf13/viper"
)

// SubscriptionSettings config is used by a subscriber to specify what eth data to stream from the watcher
type SubscriptionSettings struct {
	BackFill      bool
	BackFillOnly  bool
	Start         *big.Int
	End           *big.Int // set to 0 or a negative value to have no ending block
	HeaderFilter  HeaderFilter
	TxFilter      TxFilter
	ReceiptFilter ReceiptFilter
	StateFilter   StateFilter
	StorageFilter StorageFilter
}

// HeaderFilter contains filter settings for headers
type HeaderFilter struct {
	Off    bool
	Uncles bool
}

// TxFilter contains filter settings for txs
type TxFilter struct {
	Off bool
	Src []string
	Dst []string
}

// ReceiptFilter contains filter settings for receipts
type ReceiptFilter struct {
	Off bool
	// TODO: change this so that we filter for receipts first and we always return the corresponding transaction
	MatchTxs     bool     // turn on to retrieve receipts that pair with retrieved transactions
	LogAddresses []string // receipt contains logs from the provided addresses
	Topics       [][]string
}

// StateFilter contains filter settings for state
type StateFilter struct {
	Off               bool
	Addresses         []string // is converted to state key by taking its keccak256 hash
	IntermediateNodes bool
}

// StorageFilter contains filter settings for storage
type StorageFilter struct {
	Off               bool
	Addresses         []string
	StorageKeys       []string // need to be the hashs key themselves not slot position
	IntermediateNodes bool
}

// Init is used to initialize a EthSubscription struct with env variables
func NewEthSubscriptionConfig() (*SubscriptionSettings, error) {
	sc := new(SubscriptionSettings)
	// Below default to false, which means we do not backfill by default
	sc.BackFill = viper.GetBool("watcher.ethSubscription.historicalData")
	sc.BackFillOnly = viper.GetBool("watcher.ethSubscription.historicalDataOnly")
	// Below default to 0
	// 0 start means we start at the beginning and 0 end means we continue indefinitely
	sc.Start = big.NewInt(viper.GetInt64("watcher.ethSubscription.startingBlock"))
	sc.End = big.NewInt(viper.GetInt64("watcher.ethSubscription.endingBlock"))
	// Below default to false, which means we get all headers and no uncles by default
	sc.HeaderFilter = HeaderFilter{
		Off:    viper.GetBool("watcher.ethSubscription.headerFilter.off"),
		Uncles: viper.GetBool("watcher.ethSubscription.headerFilter.uncles"),
	}
	// Below defaults to false and two slices of length 0
	// Which means we get all transactions by default
	sc.TxFilter = TxFilter{
		Off: viper.GetBool("watcher.ethSubscription.txFilter.off"),
		Src: viper.GetStringSlice("watcher.ethSubscription.txFilter.src"),
		Dst: viper.GetStringSlice("watcher.ethSubscription.txFilter.dst"),
	}
	// By default all of the topic slices will be empty => match on any/all topics
	topics := make([][]string, 4)
	topics[0] = viper.GetStringSlice("watcher.ethSubscription.receiptFilter.topic0s")
	topics[1] = viper.GetStringSlice("watcher.ethSubscription.receiptFilter.topic1s")
	topics[2] = viper.GetStringSlice("watcher.ethSubscription.receiptFilter.topic2s")
	topics[3] = viper.GetStringSlice("watcher.ethSubscription.receiptFilter.topic3s")
	sc.ReceiptFilter = ReceiptFilter{
		Off:          viper.GetBool("watcher.ethSubscription.receiptFilter.off"),
		MatchTxs:     viper.GetBool("watcher.ethSubscription.receiptFilter.matchTxs"),
		LogAddresses: viper.GetStringSlice("watcher.ethSubscription.receiptFilter.contracts"),
		Topics:       topics,
	}
	// Below defaults to two false, and a slice of length 0
	// Which means we get all state leafs by default, but no intermediate nodes
	sc.StateFilter = StateFilter{
		Off:               viper.GetBool("watcher.ethSubscription.stateFilter.off"),
		IntermediateNodes: viper.GetBool("watcher.ethSubscription.stateFilter.intermediateNodes"),
		Addresses:         viper.GetStringSlice("watcher.ethSubscription.stateFilter.addresses"),
	}
	// Below defaults to two false, and two slices of length 0
	// Which means we get all storage leafs by default, but no intermediate nodes
	sc.StorageFilter = StorageFilter{
		Off:               viper.GetBool("watcher.ethSubscription.storageFilter.off"),
		IntermediateNodes: viper.GetBool("watcher.ethSubscription.storageFilter.intermediateNodes"),
		Addresses:         viper.GetStringSlice("watcher.ethSubscription.storageFilter.addresses"),
		StorageKeys:       viper.GetStringSlice("watcher.ethSubscription.storageFilter.storageKeys"),
	}
	return sc, nil
}
