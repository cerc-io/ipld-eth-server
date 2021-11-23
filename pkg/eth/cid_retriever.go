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
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

// Retriever interface for substituting mocks in tests
type Retriever interface {
	RetrieveFirstBlockNumber(ctx context.Context) (int64, error)
	RetrieveLastBlockNumber(ctx context.Context) (int64, error)
	Retrieve(ctx context.Context, filter SubscriptionSettings, blockNumber int64) ([]CIDWrapper, bool, error)
}

// CIDRetriever satisfies the CIDRetriever interface for ethereum
type CIDRetriever struct {
	db sql.Database
}

// NewCIDRetriever returns a pointer to a new CIDRetriever which supports the CIDRetriever interface
func NewCIDRetriever(db sql.Database) *CIDRetriever {
	return &CIDRetriever{
		db: db,
	}
}

// RetrieveFirstBlockNumber is used to retrieve the first block number in the db
func (ecr *CIDRetriever) RetrieveFirstBlockNumber(ctx context.Context) (int64, error) {
	var blockNumber int64
	err := ecr.db.Get(ctx, &blockNumber, "SELECT block_number FROM eth.header_cids ORDER BY block_number ASC LIMIT 1")
	return blockNumber, err
}

// RetrieveLastBlockNumber is used to retrieve the latest block number in the db
func (ecr *CIDRetriever) RetrieveLastBlockNumber(ctx context.Context) (int64, error) {
	var blockNumber int64
	err := ecr.db.Get(ctx, &blockNumber, "SELECT block_number FROM eth.header_cids ORDER BY block_number DESC LIMIT 1 ")
	return blockNumber, err
}

// Retrieve is used to retrieve all of the CIDs which conform to the passed StreamFilters
func (ecr *CIDRetriever) Retrieve(ctx context.Context, filter SubscriptionSettings, blockNumber int64) ([]CIDWrapper, bool, error) {
	log.Debug("retrieving cids")

	// Begin new db tx
	tx, err := ecr.db.Begin(ctx)
	if err != nil {
		return nil, true, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(ctx, tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(ctx, tx)
		} else {
			err = tx.Commit(ctx)
		}
	}()

	// Retrieve cached header CIDs at this block height
	var headers []models.HeaderModel
	headers, err = ecr.RetrieveHeaderCIDs(ctx, tx, blockNumber)
	if err != nil {
		log.Error("header cid retrieval error", err)
		return nil, true, err
	}
	cws := make([]CIDWrapper, len(headers))
	empty := true
	for i, header := range headers {
		cw := new(CIDWrapper)
		cw.BlockNumber = big.NewInt(blockNumber)
		if !filter.HeaderFilter.Off {
			cw.Header = header
			empty = false
			if filter.HeaderFilter.Uncles {
				// Retrieve uncle cids for this header id
				var uncleCIDs []models.UncleModel
				uncleCIDs, err = ecr.RetrieveUncleCIDsByHeaderID(ctx, tx, header.BlockHash)
				if err != nil {
					log.Error("uncle cid retrieval error")
					return nil, true, err
				}
				cw.Uncles = uncleCIDs
			}
		}
		// Retrieve cached trx CIDs
		if !filter.TxFilter.Off {
			cw.Transactions, err = ecr.RetrieveTxCIDs(ctx, tx, filter.TxFilter, header.BlockHash)
			if err != nil {
				log.Error("transaction cid retrieval error")
				return nil, true, err
			}
			if len(cw.Transactions) > 0 {
				empty = false
			}
		}
		trxHashes := make([]string, len(cw.Transactions))
		for j, t := range cw.Transactions {
			trxHashes[j] = t.TxHash
		}
		// Retrieve cached receipt CIDs
		if !filter.ReceiptFilter.Off {
			cw.Receipts, err = ecr.RetrieveRctCIDsByHeaderID(ctx, tx, filter.ReceiptFilter, header.BlockHash, trxHashes)
			if err != nil {
				log.Error("receipt cid retrieval error")
				return nil, true, err
			}
			if len(cw.Receipts) > 0 {
				empty = false
			}
		}
		// Retrieve cached state CIDs
		if !filter.StateFilter.Off {
			cw.StateNodes, err = ecr.RetrieveStateCIDs(ctx, tx, filter.StateFilter, header.BlockHash)
			if err != nil {
				log.Error("state cid retrieval error")
				return nil, true, err
			}
			if len(cw.StateNodes) > 0 {
				empty = false
			}
		}
		// Retrieve cached storage CIDs
		if !filter.StorageFilter.Off {
			cw.StorageNodes, err = ecr.RetrieveStorageCIDs(ctx, tx, filter.StorageFilter, header.BlockHash)
			if err != nil {
				log.Error("storage cid retrieval error")
				return nil, true, err
			}
			if len(cw.StorageNodes) > 0 {
				empty = false
			}
		}
		cws[i] = *cw
	}

	return cws, empty, err
}

// RetrieveHeaderCIDs retrieves and returns all of the header cids at the provided blockheight
func (ecr *CIDRetriever) RetrieveHeaderCIDs(ctx context.Context, tx sql.Tx, blockNumber int64) ([]models.HeaderModel, error) {
	log.Debug("retrieving header cids for block ", blockNumber)
	headers := make([]models.HeaderModel, 0)
	pgStr := `SELECT * FROM eth.header_cids
				WHERE block_number = $1`
	return headers, tx.QueryRow(ctx, pgStr, blockNumber).Scan(&headers)
}

// RetrieveUncleCIDsByHeaderID retrieves and returns all of the uncle cids for the provided header
func (ecr *CIDRetriever) RetrieveUncleCIDsByHeaderID(ctx context.Context, tx sql.Tx, headerID string) ([]models.UncleModel, error) {
	log.Debug("retrieving uncle cids for block id ", headerID)
	headers := make([]models.UncleModel, 0)
	pgStr := `SELECT * FROM eth.uncle_cids
				WHERE header_id = $1`

	return headers, tx.QueryRow(ctx, pgStr, headerID).Scan(headers)
}

// RetrieveTxCIDs retrieves and returns all of the trx cids at the provided blockheight that conform to the provided filter parameters
// also returns the ids for the returned transaction cids
func (ecr *CIDRetriever) RetrieveTxCIDs(ctx context.Context, tx sql.Tx, txFilter TxFilter, headerID string) ([]models.TxModel, error) {
	log.Debug("retrieving transaction cids for header id ", headerID)
	args := make([]interface{}, 0, 3)
	results := make([]models.TxModel, 0)
	id := 1
	pgStr := fmt.Sprintf(`SELECT transaction_cids.id, transaction_cids.header_id,
 			transaction_cids.tx_hash, transaction_cids.cid, transaction_cids.mh_key,
 			transaction_cids.dst, transaction_cids.src, transaction_cids.index, transaction_cids.tx_data
 			FROM eth.transaction_cids INNER JOIN eth.header_cids ON (transaction_cids.header_id = header_cids.id)
			WHERE header_cids.id = $%d`, id)
	args = append(args, headerID)
	id++
	if len(txFilter.Dst) > 0 {
		pgStr += fmt.Sprintf(` AND transaction_cids.dst = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(txFilter.Dst))
		id++
	}
	if len(txFilter.Src) > 0 {
		pgStr += fmt.Sprintf(` AND transaction_cids.src = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(txFilter.Src))
	}
	pgStr += ` ORDER BY transaction_cids.index`
	return results, tx.QueryRow(ctx, pgStr, args...).Scan(results)
}

func topicFilterCondition(id *int, topics [][]string, args []interface{}, pgStr string, first bool) (string, []interface{}) {
	for i, topicSet := range topics {
		if len(topicSet) == 0 {
			continue
		}

		if !first {
			pgStr += " AND"
		} else {
			first = false
		}
		pgStr += fmt.Sprintf(` eth.log_cids.topic%d = ANY ($%d)`, i, *id)
		args = append(args, pq.Array(topicSet))
		*id++
	}
	return pgStr, args
}

func logFilterCondition(id *int, pgStr string, args []interface{}, rctFilter ReceiptFilter) (string, []interface{}) {
	if len(rctFilter.LogAddresses) > 0 {
		pgStr += fmt.Sprintf(` AND eth.log_cids.address = ANY ($%d)`, *id)
		args = append(args, pq.Array(rctFilter.LogAddresses))
		*id++
	}

	// Filter on topics if there are any
	if hasTopics(rctFilter.Topics) {
		pgStr, args = topicFilterCondition(id, rctFilter.Topics, args, pgStr, false)
	}

	return pgStr, args
}

func receiptFilterConditions(id *int, pgStr string, args []interface{}, rctFilter ReceiptFilter, txHashes []string) (string, []interface{}) {
	rctCond := " AND (receipt_cids.id = ANY ( "
	logQuery := "SELECT receipt_id FROM eth.log_cids WHERE"
	if len(rctFilter.LogAddresses) > 0 {
		// Filter on log contract addresses if there are any
		pgStr += fmt.Sprintf(`%s %s eth.log_cids.address = ANY ($%d)`, rctCond, logQuery, *id)
		args = append(args, pq.Array(rctFilter.LogAddresses))
		*id++

		// Filter on topics if there are any
		if hasTopics(rctFilter.Topics) {
			pgStr, args = topicFilterCondition(id, rctFilter.Topics, args, pgStr, false)
		}

		pgStr += ")"

		// Filter on txHashes if there are any, and we are matching txs
		if rctFilter.MatchTxs && len(txHashes) > 0 {
			pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d::STRING[])`, *id)
			args = append(args, pq.Array(txHashes))
		}
		pgStr += ")"
	} else { // If there are no contract addresses to filter on
		// Filter on topics if there are any
		if hasTopics(rctFilter.Topics) {
			pgStr += rctCond + logQuery
			pgStr, args = topicFilterCondition(id, rctFilter.Topics, args, pgStr, true)
			pgStr += ")"
			// Filter on txHashes if there are any, and we are matching txs
			if rctFilter.MatchTxs && len(txHashes) > 0 {
				pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d::STRING[])`, *id)
				args = append(args, pq.Array(txHashes))
			}
			pgStr += ")"
		} else if rctFilter.MatchTxs && len(txHashes) > 0 {
			// If there are no contract addresses or topics to filter on,
			// Filter on txHashes if there are any, and we are matching txs
			pgStr += fmt.Sprintf(` AND receipt_cids.tx_id = ANY($%d::STRING[])`, *id)
			args = append(args, pq.Array(txHashes))
		}
	}

	return pgStr, args
}

// RetrieveRctCIDsByHeaderID retrieves and returns all of the rct cids at the provided header ID that conform to the provided
// filter parameters and correspond to the provided tx ids
func (ecr *CIDRetriever) RetrieveRctCIDsByHeaderID(ctx context.Context, tx sql.Tx, rctFilter ReceiptFilter, headerID string, trxHashes []string) ([]models.ReceiptModel, error) {
	log.Debug("retrieving receipt cids for header id ", headerID)
	args := make([]interface{}, 0, 4)
	pgStr := `SELECT receipt_cids.id, receipt_cids.tx_id, receipt_cids.leaf_cid, receipt_cids.leaf_mh_key,
 			receipt_cids.contract, receipt_cids.contract_hash
 			FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
			WHERE receipt_cids.tx_id = transaction_cids.id 
			AND transaction_cids.header_id = header_cids.id
			AND header_cids.id = $1`
	id := 2
	args = append(args, headerID)

	pgStr, args = receiptFilterConditions(&id, pgStr, args, rctFilter, trxHashes)

	pgStr += ` ORDER BY transaction_cids.index`
	receiptCids := make([]models.ReceiptModel, 0)
	return receiptCids, tx.QueryRow(ctx, pgStr, args...).Scan(receiptCids)
}

// RetrieveFilteredGQLLogs retrieves and returns all the log cIDs provided blockHash that conform to the provided
// filter parameters.
func (ecr *CIDRetriever) RetrieveFilteredGQLLogs(ctx context.Context, tx sql.Tx, rctFilter ReceiptFilter, blockHash *common.Hash) ([]LogResult, error) {
	log.Debug("retrieving log cids for receipt ids")
	args := make([]interface{}, 0, 4)
	id := 1
	pgStr := `SELECT eth.log_cids.leaf_cid, eth.log_cids.index, eth.log_cids.rct_id,  
       			eth.log_cids.address, eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3, 
       			eth.log_cids.log_data, eth.transaction_cids.tx_hash, data, eth.receipt_cids.leaf_cid as cid, eth.receipt_cids.post_status
				FROM eth.log_cids, eth.receipt_cids, eth.transaction_cids, eth.header_cids, public.blocks
				WHERE eth.log_cids.receipt_id = receipt_cids.id
				AND receipt_cids.tx_id = transaction_cids.id
 				AND transaction_cids.header_id = header_cids.id
 				AND log_cids.leaf_mh_key = blocks.key AND header_cids.block_hash = $1`

	args = append(args, blockHash.String())
	id++

	pgStr, args = logFilterCondition(&id, pgStr, args, rctFilter)
	pgStr += ` ORDER BY log_cids.index`

	logCIDs := make([]LogResult, 0)
	return logCIDs, tx.QueryRow(ctx, pgStr, args...).Scan(&logCIDs)
}

// RetrieveFilteredLog retrieves and returns all the log cIDs provided blockHeight or blockHash that conform to the provided
// filter parameters.
func (ecr *CIDRetriever) RetrieveFilteredLog(ctx context.Context, tx sql.Tx, rctFilter ReceiptFilter, blockNumber int64, blockHash *common.Hash) ([]LogResult, error) {
	log.Debug("retrieving log cids for receipt ids")
	args := make([]interface{}, 0, 4)
	pgStr := `SELECT eth.log_cids.leaf_cid, eth.log_cids.index, eth.log_cids.rct_id,  
       			eth.log_cids.address, eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3, 
       			eth.log_cids.log_data, eth.transaction_cids.tx_hash, eth.transaction_cids.index as txn_index, 
       			header_cids.block_hash, header_cids.block_number
				FROM eth.log_cids, eth.receipt_cids, eth.transaction_cids, eth.header_cids
				WHERE eth.log_cids.receipt_id = receipt_cids.id
				AND receipt_cids.tx_id = transaction_cids.id
 				AND transaction_cids.header_id = header_cids.id`
	id := 1
	if blockNumber > 0 {
		pgStr += fmt.Sprintf(` AND header_cids.block_number = $%d`, id)
		args = append(args, blockNumber)
		id++
	}
	if blockHash != nil {
		pgStr += fmt.Sprintf(` AND header_cids.block_hash = $%d`, id)
		args = append(args, blockHash.String())
		id++
	}

	pgStr, args = logFilterCondition(&id, pgStr, args, rctFilter)
	pgStr += ` ORDER BY log_cids.index`

	logCIDs := make([]LogResult, 0)
	return logCIDs, tx.QueryRow(ctx, pgStr, args...).Scan(&logCIDs)
}

// RetrieveRctCIDs retrieves and returns all of the rct cids at the provided blockheight or block hash that conform to the provided
// filter parameters and correspond to the provided tx ids
func (ecr *CIDRetriever) RetrieveRctCIDs(tx *sqlx.Tx, rctFilter ReceiptFilter, blockNumber int64, blockHash *common.Hash, txHashes []string) ([]models.ReceiptModel, error) {
	log.Debug("retrieving receipt cids for block ", blockNumber)
	args := make([]interface{}, 0, 5)
	pgStr := `SELECT receipt_cids.id, receipt_cids.leaf_cid, receipt_cids.leaf_mh_key, receipt_cids.tx_id
 			FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
			WHERE receipt_cids.tx_id = transaction_cids.id 
			AND transaction_cids.header_id = header_cids.id`
	id := 1
	if blockNumber > 0 {
		pgStr += fmt.Sprintf(` AND header_cids.block_number = $%d`, id)
		args = append(args, blockNumber)
		id++
	}
	if blockHash != nil {
		pgStr += fmt.Sprintf(` AND header_cids.block_hash = $%d`, id)
		args = append(args, blockHash.String())
		id++
	}

	pgStr, args = receiptFilterConditions(&id, pgStr, args, rctFilter, txHashes)

	pgStr += ` ORDER BY transaction_cids.index`
	receiptCids := make([]models.ReceiptModel, 0)
	return receiptCids, tx.Select(&receiptCids, pgStr, args...)
}

func hasTopics(topics [][]string) bool {
	for _, topicSet := range topics {
		if len(topicSet) > 0 {
			return true
		}
	}
	return false
}

// RetrieveStateCIDs retrieves and returns all of the state node cids at the provided header ID that conform to the provided filter parameters
func (ecr *CIDRetriever) RetrieveStateCIDs(ctx context.Context, tx sql.Tx, stateFilter StateFilter, headerID string) ([]models.StateNodeModel, error) {
	log.Debug("retrieving state cids for header id ", headerID)
	args := make([]interface{}, 0, 2)
	pgStr := `SELECT state_cids.id, state_cids.header_id,
			state_cids.state_leaf_key, state_cids.node_type, state_cids.cid, state_cids.mh_key, state_cids.state_path
			FROM eth.state_cids INNER JOIN eth.header_cids ON (state_cids.header_id = header_cids.id)
			WHERE header_cids.id = $1`
	args = append(args, headerID)
	addrLen := len(stateFilter.Addresses)
	if addrLen > 0 {
		keys := make([]string, addrLen)
		for i, addr := range stateFilter.Addresses {
			keys[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes()).String()
		}
		pgStr += ` AND state_cids.state_leaf_key = ANY($2::VARCHAR(66)[])`
		args = append(args, pq.Array(keys))
	}
	if !stateFilter.IntermediateNodes {
		pgStr += ` AND state_cids.node_type = 2`
	}
	stateNodeCIDs := make([]models.StateNodeModel, 0)
	return stateNodeCIDs, tx.QueryRow(ctx, pgStr, args...).Scan(&stateNodeCIDs)
}

// RetrieveStorageCIDs retrieves and returns all of the storage node cids at the provided header id that conform to the provided filter parameters
func (ecr *CIDRetriever) RetrieveStorageCIDs(ctx context.Context, tx sql.Tx, storageFilter StorageFilter, headerID string) ([]models.StorageNodeWithStateKeyModel, error) {
	log.Debug("retrieving storage cids for header id ", headerID)
	args := make([]interface{}, 0, 3)
	pgStr := `SELECT storage_cids.id, storage_cids.state_id, storage_cids.storage_leaf_key, storage_cids.node_type,
 			storage_cids.cid, storage_cids.mh_key, storage_cids.storage_path, state_cids.state_leaf_key
 			FROM eth.storage_cids, eth.state_cids, eth.header_cids
			WHERE storage_cids.header_id = state_cids.header_id AND storage_cids.state_path = state_cids.state_path
			AND state_cids.header_id = header_cids.block_hash
			AND header_cids.block_hash = $1`
	args = append(args, headerID)
	id := 2
	addrLen := len(storageFilter.Addresses)
	if addrLen > 0 {
		keys := make([]string, addrLen)
		for i, addr := range storageFilter.Addresses {
			keys[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes()).String()
		}
		pgStr += fmt.Sprintf(` AND state_cids.state_leaf_key = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(keys))
		id++
	}
	if len(storageFilter.StorageKeys) > 0 {
		pgStr += fmt.Sprintf(` AND storage_cids.storage_leaf_key = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(storageFilter.StorageKeys))
	}
	if !storageFilter.IntermediateNodes {
		pgStr += ` AND storage_cids.node_type = 2`
	}
	storageNodeCIDs := make([]models.StorageNodeWithStateKeyModel, 0)
	return storageNodeCIDs, tx.QueryRow(ctx, pgStr, args...).Scan(&storageNodeCIDs)
}

// RetrieveBlockByHash returns all of the CIDs needed to compose an entire block, for a given block hash
func (ecr *CIDRetriever) RetrieveBlockByHash(ctx context.Context, blockHash common.Hash) (models.HeaderModel, []models.UncleModel, []models.TxModel, []models.ReceiptModel, error) {
	log.Debug("retrieving block cids for block hash ", blockHash.String())

	// Begin new db tx
	tx, err := ecr.db.Begin(ctx)
	if err != nil {
		return models.HeaderModel{}, nil, nil, nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(ctx, tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(ctx, tx)
		} else {
			err = tx.Commit(ctx)
		}
	}()

	var headerCID models.HeaderModel
	headerCID, err = ecr.RetrieveHeaderCIDByHash(ctx, tx, blockHash)
	if err != nil {
		log.Error("header cid retrieval error")
		return models.HeaderModel{}, nil, nil, nil, err
	}
	var uncleCIDs []models.UncleModel
	uncleCIDs, err = ecr.RetrieveUncleCIDsByHeaderID(ctx, tx, headerCID.BlockHash)
	if err != nil {
		log.Error("uncle cid retrieval error")
		return models.HeaderModel{}, nil, nil, nil, err
	}
	var txCIDs []models.TxModel
	txCIDs, err = ecr.RetrieveTxCIDsByHeaderID(ctx, tx, headerCID.BlockHash)
	if err != nil {
		log.Error("tx cid retrieval error")
		return models.HeaderModel{}, nil, nil, nil, err
	}
	txHashes := make([]string, len(txCIDs))
	for i, txCID := range txCIDs {
		txHashes[i] = txCID.TxHash
	}
	var rctCIDs []models.ReceiptModel
	rctCIDs, err = ecr.RetrieveReceiptCIDsByTxIDs(ctx, tx, txHashes)
	if err != nil {
		log.Error("rct cid retrieval error")
	}
	return headerCID, uncleCIDs, txCIDs, rctCIDs, err
}

// RetrieveBlockByNumber returns all of the CIDs needed to compose an entire block, for a given block number
func (ecr *CIDRetriever) RetrieveBlockByNumber(ctx context.Context, blockNumber int64) (models.HeaderModel, []models.UncleModel, []models.TxModel, []models.ReceiptModel, error) {
	log.Debug("retrieving block cids for block number ", blockNumber)

	// Begin new db tx
	tx, err := ecr.db.Begin(ctx)
	if err != nil {
		return models.HeaderModel{}, nil, nil, nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(ctx, tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(ctx, tx)
		} else {
			err = tx.Commit(ctx)
		}
	}()

	var headerCID []models.HeaderModel
	headerCID, err = ecr.RetrieveHeaderCIDs(ctx, tx, blockNumber)
	if err != nil {
		log.Error("header cid retrieval error")
		return models.HeaderModel{}, nil, nil, nil, err
	}
	if len(headerCID) < 1 {
		return models.HeaderModel{}, nil, nil, nil, fmt.Errorf("header cid retrieval error, no header CIDs found at block %d", blockNumber)
	}
	var uncleCIDs []models.UncleModel
	uncleCIDs, err = ecr.RetrieveUncleCIDsByHeaderID(ctx, tx, headerCID[0].BlockHash)
	if err != nil {
		log.Error("uncle cid retrieval error")
		return models.HeaderModel{}, nil, nil, nil, err
	}
	var txCIDs []models.TxModel
	txCIDs, err = ecr.RetrieveTxCIDsByHeaderID(ctx, tx, headerCID[0].BlockHash)
	if err != nil {
		log.Error("tx cid retrieval error")
		return models.HeaderModel{}, nil, nil, nil, err
	}
	txHashes := make([]string, len(txCIDs))
	for i, txCID := range txCIDs {
		txHashes[i] = txCID.TxHash
	}
	var rctCIDs []models.ReceiptModel
	rctCIDs, err = ecr.RetrieveReceiptCIDsByTxIDs(ctx, tx, txHashes)
	if err != nil {
		log.Error("rct cid retrieval error")
	}
	return headerCID[0], uncleCIDs, txCIDs, rctCIDs, err
}

// RetrieveHeaderCIDByHash returns the header for the given block hash
func (ecr *CIDRetriever) RetrieveHeaderCIDByHash(ctx context.Context, tx sql.Tx, blockHash common.Hash) (models.HeaderModel, error) {
	log.Debug("retrieving header cids for block hash ", blockHash.String())
	pgStr := `SELECT * FROM eth.header_cids
			WHERE block_hash = $1`
	var headerCID models.HeaderModel
	return headerCID, tx.QueryRow(ctx, pgStr, blockHash.String()).Scan(&headerCID.CID, &headerCID.NodeID, &headerCID.BlockHash, &headerCID.BlockNumber,
		&headerCID.BaseFee, &headerCID.Bloom, &headerCID.MhKey, &headerCID.ParentHash, &headerCID.RctRoot, &headerCID.Reward, &headerCID.StateRoot,
		&headerCID.Timestamp, &headerCID.TimesValidated, &headerCID.TotalDifficulty, &headerCID.TxRoot, &headerCID.UncleRoot)
}

// RetrieveTxCIDsByHeaderID retrieves all tx CIDs for the given header id
func (ecr *CIDRetriever) RetrieveTxCIDsByHeaderID(ctx context.Context, tx sql.Tx, headerID string) ([]models.TxModel, error) {
	log.Debug("retrieving tx cids for block id ", headerID)
	pgStr := `SELECT * FROM eth.transaction_cids
			WHERE header_id = $1
			ORDER BY index`
	var txCIDs []models.TxModel
	return txCIDs, tx.QueryRow(ctx, pgStr, headerID).(*sqlx.Row).Scan(&txCIDs)
}

// RetrieveReceiptCIDsByTxIDs retrieves receipt CIDs by their associated tx IDs
func (ecr *CIDRetriever) RetrieveReceiptCIDsByTxIDs(ctx context.Context, tx sql.Tx, txHashes []string) ([]models.ReceiptModel, error) {
	log.Debugf("retrieving receipt cids for tx ids %v", txHashes)
	pgStr := `SELECT receipt_cids.id, receipt_cids.tx_id, receipt_cids.leaf_cid, receipt_cids.leaf_mh_key,
 			receipt_cids.contract, receipt_cids.contract_hash
			FROM eth.receipt_cids, eth.transaction_cids
			WHERE tx_id = ANY($1::INTEGER[])
			AND receipt_cids.tx_id = transaction_cids.id
			ORDER BY transaction_cids.index`
	var rctCIDs []models.ReceiptModel
	return rctCIDs, tx.QueryRow(ctx, pgStr, pq.Array(txHashes)).Scan(rctCIDs)
}
