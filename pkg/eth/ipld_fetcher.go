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
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/jmoiron/sqlx"
	log "github.com/sirupsen/logrus"
	"github.com/thoas/go-funk"
	"github.com/vulcanize/ipld-eth-server/v4/pkg/shared"
)

// Fetcher interface for substituting mocks in tests
type Fetcher interface {
	Fetch(cids CIDWrapper) (*IPLDs, error)
}

// IPLDFetcher satisfies the IPLDFetcher interface for ethereum
// It interfaces directly with PG-IPFS
type IPLDFetcher struct {
	db *sqlx.DB
}

// NewIPLDFetcher creates a pointer to a new IPLDFetcher
func NewIPLDFetcher(db *sqlx.DB) *IPLDFetcher {
	return &IPLDFetcher{
		db: db,
	}
}

// Fetch is the exported method for fetching and returning all the IPLDS specified in the CIDWrapper
func (f *IPLDFetcher) Fetch(cids CIDWrapper) (*IPLDs, error) {
	log.Debug("fetching iplds")
	iplds := new(IPLDs)
	var ok bool
	iplds.TotalDifficulty, ok = new(big.Int).SetString(cids.Header.TotalDifficulty, 10)
	if !ok {
		return nil, errors.New("eth fetcher: unable to set total difficulty")
	}
	iplds.BlockNumber = cids.BlockNumber

	tx, err := f.db.Beginx()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(tx)
		} else {
			err = tx.Commit()
		}
	}()

	iplds.Header, err = f.FetchHeader(tx, cids.Header)
	if err != nil {
		return nil, fmt.Errorf("eth pg fetcher: header fetching error: %s", err.Error())
	}
	iplds.Uncles, err = f.FetchUncles(tx, cids.Uncles)
	if err != nil {
		return nil, fmt.Errorf("eth pg fetcher: uncle fetching error: %s", err.Error())
	}
	iplds.Transactions, err = f.FetchTrxs(tx, cids.Transactions)
	if err != nil {
		return nil, fmt.Errorf("eth pg fetcher: transaction fetching error: %s", err.Error())
	}
	iplds.Receipts, err = f.FetchRcts(tx, cids.Receipts)
	if err != nil {
		return nil, fmt.Errorf("eth pg fetcher: receipt fetching error: %s", err.Error())
	}
	iplds.StateNodes, err = f.FetchState(tx, cids.StateNodes)
	if err != nil {
		return nil, fmt.Errorf("eth pg fetcher: state fetching error: %s", err.Error())
	}
	iplds.StorageNodes, err = f.FetchStorage(tx, cids.StorageNodes)
	if err != nil {
		return nil, fmt.Errorf("eth pg fetcher: storage fetching error: %s", err.Error())
	}
	return iplds, err
}

// FetchHeader fetches header
func (f *IPLDFetcher) FetchHeader(tx *sqlx.Tx, c models.HeaderModel) (models.IPLDModel, error) {
	log.Debug("fetching header ipld")
	blockNumber, err := strconv.ParseUint(c.BlockNumber, 10, 64)
	if err != nil {
		return models.IPLDModel{}, err
	}

	headerBytes, err := shared.FetchIPLDByMhKeyAndBlockNumber(tx, c.MhKey, blockNumber)
	if err != nil {
		return models.IPLDModel{}, err
	}
	return models.IPLDModel{
		BlockNumber: c.BlockNumber,
		Data:        headerBytes,
		Key:         c.CID,
	}, nil
}

// FetchHeaders fetches headers
func (f *IPLDFetcher) FetchHeaders(tx *sqlx.Tx, cids []models.HeaderModel) ([]models.IPLDModel, error) {
	log.Debug("fetching header iplds")
	headerIPLDs := make([]models.IPLDModel, len(cids))

	blockNumbers := make([]uint64, len(cids))
	mhKeys := make([]string, len(cids))
	for i, c := range cids {
		var err error
		mhKeys[i] = c.MhKey
		blockNumbers[i], err = strconv.ParseUint(c.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	fetchedIPLDs, err := shared.FetchIPLDsByMhKeysAndBlockNumbers(tx, mhKeys, blockNumbers)
	if err != nil {
		return nil, err
	}

	for i, c := range cids {
		headerIPLD := funk.Find(fetchedIPLDs, func(ipld models.IPLDModel) bool {
			return ipld.Key == c.MhKey
		}).(models.IPLDModel)

		headerIPLDs[i] = headerIPLD
	}

	return headerIPLDs, nil
}

// FetchUncles fetches uncles
func (f *IPLDFetcher) FetchUncles(tx *sqlx.Tx, cids []models.UncleModel) ([]models.IPLDModel, error) {
	log.Debug("fetching uncle iplds")
	uncleIPLDs := make([]models.IPLDModel, len(cids))
	for i, c := range cids {
		blockNumber, err := strconv.ParseUint(c.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}
		uncleBytes, err := shared.FetchIPLDByMhKeyAndBlockNumber(tx, c.MhKey, blockNumber)
		if err != nil {
			return nil, err
		}
		uncleIPLDs[i] = models.IPLDModel{
			BlockNumber: c.BlockNumber,
			Data:        uncleBytes,
			Key:         c.CID,
		}
	}
	return uncleIPLDs, nil
}

// FetchTrxs fetches transactions
func (f *IPLDFetcher) FetchTrxs(tx *sqlx.Tx, cids []models.TxModel) ([]models.IPLDModel, error) {
	log.Debug("fetching transaction iplds")
	trxIPLDs := make([]models.IPLDModel, len(cids))
	for i, c := range cids {
		blockNumber, err := strconv.ParseUint(c.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}
		txBytes, err := shared.FetchIPLDByMhKeyAndBlockNumber(tx, c.MhKey, blockNumber)
		if err != nil {
			return nil, err
		}
		trxIPLDs[i] = models.IPLDModel{
			BlockNumber: c.BlockNumber,
			Data:        txBytes,
			Key:         c.CID,
		}
	}
	return trxIPLDs, nil
}

// FetchRcts fetches receipts
func (f *IPLDFetcher) FetchRcts(tx *sqlx.Tx, cids []models.ReceiptModel) ([]models.IPLDModel, error) {
	log.Debug("fetching receipt iplds")
	rctIPLDs := make([]models.IPLDModel, len(cids))
	for i, c := range cids {
		blockNumber, err := strconv.ParseUint(c.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}
		rctBytes, err := shared.FetchIPLDByMhKeyAndBlockNumber(tx, c.LeafMhKey, blockNumber)
		if err != nil {
			return nil, err
		}
		//nodeVal, err := DecodeLeafNode(rctBytes)
		rctIPLDs[i] = models.IPLDModel{
			BlockNumber: c.BlockNumber,
			Data:        rctBytes,
			Key:         c.LeafCID,
		}
	}
	return rctIPLDs, nil
}

// FetchState fetches state nodes
func (f *IPLDFetcher) FetchState(tx *sqlx.Tx, cids []models.StateNodeModel) ([]StateNode, error) {
	log.Debug("fetching state iplds")
	stateNodes := make([]StateNode, 0, len(cids))
	for _, stateNode := range cids {
		if stateNode.CID == "" {
			continue
		}
		blockNumber, err := strconv.ParseUint(stateNode.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}
		stateBytes, err := shared.FetchIPLDByMhKeyAndBlockNumber(tx, stateNode.MhKey, blockNumber)
		if err != nil {
			return nil, err
		}
		stateNodes = append(stateNodes, StateNode{
			IPLD: models.IPLDModel{
				BlockNumber: stateNode.BlockNumber,
				Data:        stateBytes,
				Key:         stateNode.CID,
			},
			StateLeafKey: common.HexToHash(stateNode.StateKey),
			Type:         ResolveToNodeType(stateNode.NodeType),
			Path:         stateNode.Path,
		})
	}
	return stateNodes, nil
}

// FetchStorage fetches storage nodes
func (f *IPLDFetcher) FetchStorage(tx *sqlx.Tx, cids []models.StorageNodeWithStateKeyModel) ([]StorageNode, error) {
	log.Debug("fetching storage iplds")
	storageNodes := make([]StorageNode, 0, len(cids))
	for _, storageNode := range cids {
		if storageNode.CID == "" || storageNode.StateKey == "" {
			continue
		}
		blockNumber, err := strconv.ParseUint(storageNode.BlockNumber, 10, 64)
		if err != nil {
			return nil, err
		}
		storageBytes, err := shared.FetchIPLDByMhKeyAndBlockNumber(tx, storageNode.MhKey, blockNumber)
		if err != nil {
			return nil, err
		}
		storageNodes = append(storageNodes, StorageNode{
			IPLD: models.IPLDModel{
				BlockNumber: storageNode.BlockNumber,
				Data:        storageBytes,
				Key:         storageNode.CID,
			},
			StateLeafKey:   common.HexToHash(storageNode.StateKey),
			StorageLeafKey: common.HexToHash(storageNode.StorageKey),
			Type:           ResolveToNodeType(storageNode.NodeType),
			Path:           storageNode.Path,
		})
	}
	return storageNodes, nil
}
