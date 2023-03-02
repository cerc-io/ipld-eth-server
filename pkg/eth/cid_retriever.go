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
	"fmt"
	"math/big"
	"strconv"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// CIDRetriever satisfies the CIDRetriever interface for ethereum
type CIDRetriever struct {
	db     *sqlx.DB
	gormDB *gorm.DB
}

type IPLDModelRecord struct {
	models.IPLDModel
}

// TableName overrides the table name used by IPLD
func (IPLDModelRecord) TableName() string {
	return "ipld.blocks"
}

type HeaderCIDRecord struct {
	CID             string `gorm:"column:cid"`
	BlockHash       string `gorm:"primaryKey"`
	BlockNumber     string `gorm:"primaryKey"`
	ParentHash      string
	Timestamp       uint64
	StateRoot       string
	TotalDifficulty string `gorm:"column:td"`
	TxRoot          string
	RctRoot         string `gorm:"column:receipt_root"`
	UncleRoot       string
	Bloom           []byte
	MhKey           string

	// gorm doesn't check if foreign key exists in database.
	// It is required to eager load relations using preload.
	TransactionCIDs []TransactionCIDRecord `gorm:"foreignKey:HeaderID,BlockNumber;references:BlockHash,BlockNumber"`
	IPLD            IPLDModelRecord        `gorm:"foreignKey:MhKey,BlockNumber;references:Key,BlockNumber"`
}

// TableName overrides the table name used by HeaderCIDRecord
func (HeaderCIDRecord) TableName() string {
	return "eth.header_cids"
}

type TransactionCIDRecord struct {
	CID         string `gorm:"column:cid"`
	TxHash      string `gorm:"primaryKey"`
	BlockNumber string `gorm:"primaryKey"`
	HeaderID    string `gorm:"column:header_id"`
	Index       int64
	Src         string
	Dst         string
	MhKey       string
	IPLD        IPLDModelRecord `gorm:"foreignKey:MhKey,BlockNumber;references:Key,BlockNumber"`
}

// TableName overrides the table name used by TransactionCIDRecord
func (TransactionCIDRecord) TableName() string {
	return "eth.transaction_cids"
}

// NewCIDRetriever returns a pointer to a new CIDRetriever which supports the CIDRetriever interface
func NewCIDRetriever(db *sqlx.DB) *CIDRetriever {
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	if err != nil {
		log.Error(err)
		return nil
	}

	return &CIDRetriever{
		db:     db,
		gormDB: gormDB,
	}
}

// RetrieveFirstBlockNumber is used to retrieve the first block number in the db
func (ecr *CIDRetriever) RetrieveFirstBlockNumber() (int64, error) {
	var blockNumber int64
	err := ecr.db.Get(&blockNumber, "SELECT block_number FROM eth.header_cids ORDER BY block_number ASC LIMIT 1")
	return blockNumber, err
}

// RetrieveLastBlockNumber is used to retrieve the latest block number in the db
func (ecr *CIDRetriever) RetrieveLastBlockNumber() (int64, error) {
	var blockNumber int64
	err := ecr.db.Get(&blockNumber, "SELECT block_number FROM eth.header_cids ORDER BY block_number DESC LIMIT 1")
	return blockNumber, err
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
	rctCond := " AND (receipt_cids.tx_id = ANY ( "
	logQuery := "SELECT rct_id FROM eth.log_cids WHERE"
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
			pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d)`, *id)
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
				pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d)`, *id)
				args = append(args, pq.Array(txHashes))
			}
			pgStr += ")"
		} else if rctFilter.MatchTxs && len(txHashes) > 0 {
			// If there are no contract addresses or topics to filter on,
			// Filter on txHashes if there are any, and we are matching txs
			pgStr += fmt.Sprintf(` AND receipt_cids.tx_id = ANY($%d)`, *id)
			args = append(args, pq.Array(txHashes))
		}
	}

	return pgStr, args
}

// RetrieveFilteredGQLLogs retrieves and returns all the log CIDs provided blockHash that conform to the provided
// filter parameters.
func (ecr *CIDRetriever) RetrieveFilteredGQLLogs(tx *sqlx.Tx, rctFilter ReceiptFilter, blockHash *common.Hash, blockNumber *big.Int) ([]LogResult, error) {
	log.Debug("retrieving log cids for receipt ids with block hash", blockHash.String())
	args := make([]interface{}, 0, 4)
	id := 1
	pgStr := `SELECT CAST(eth.log_cids.block_number as Text), eth.log_cids.header_id as block_hash,
			eth.log_cids.cid, eth.log_cids.index, eth.log_cids.rct_id, eth.log_cids.address,
			eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3, eth.log_cids.log_data,
			data, eth.receipt_cids.cid, eth.receipt_cids.post_status, eth.receipt_cids.tx_id AS tx_hash
				FROM eth.log_cids, eth.receipt_cids, ipld.blocks
				WHERE eth.log_cids.rct_id = receipt_cids.tx_id
				AND eth.log_cids.header_id = receipt_cids.header_id
				AND eth.log_cids.block_number = receipt_cids.block_number
				AND log_cids.cid = blocks.key
				AND log_cids.block_number = blocks.block_number
				AND receipt_cids.header_id = $1`

	args = append(args, blockHash.String())
	id++

	if blockNumber != nil {
		pgStr += ` AND receipt_cids.block_number = $2`
		id++
		args = append(args, blockNumber.Int64())
	}

	pgStr, args = logFilterCondition(&id, pgStr, args, rctFilter)
	pgStr += ` ORDER BY log_cids.index`

	logCIDs := make([]LogResult, 0)
	err := tx.Select(&logCIDs, pgStr, args...)
	if err != nil {
		return nil, err
	}

	return logCIDs, nil
}

// RetrieveFilteredLog retrieves and returns all the log CIDs provided blockHeight or blockHash that conform to the provided
// filter parameters.
func (ecr *CIDRetriever) RetrieveFilteredLog(tx *sqlx.Tx, rctFilter ReceiptFilter, blockNumber int64, blockHash *common.Hash) ([]LogResult, error) {
	log.Debug("retrieving log cids for receipt ids")
	args := make([]interface{}, 0, 4)
	pgStr := `SELECT CAST(eth.log_cids.block_number as Text), eth.log_cids.cid, eth.log_cids.index, eth.log_cids.rct_id,
			eth.log_cids.address, eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3,
			eth.log_cids.log_data, eth.transaction_cids.tx_hash, eth.transaction_cids.index as txn_index,
			eth.receipt_cids.cid as cid, eth.receipt_cids.post_status, header_cids.block_hash
							FROM eth.log_cids, eth.receipt_cids, eth.transaction_cids, eth.header_cids
							WHERE eth.log_cids.rct_id = receipt_cids.tx_id
							AND eth.log_cids.header_id = eth.receipt_cids.header_id
							AND eth.log_cids.block_number = eth.receipt_cids.block_number
							AND receipt_cids.tx_id = transaction_cids.tx_hash
							AND receipt_cids.header_id = transaction_cids.header_id
							AND receipt_cids.block_number = transaction_cids.block_number
							AND transaction_cids.header_id = header_cids.block_hash
							AND transaction_cids.block_number = header_cids.block_number`
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
	err := tx.Select(&logCIDs, pgStr, args...)
	if err != nil {
		return nil, err
	}

	return logCIDs, nil
}

func hasTopics(topics [][]string) bool {
	for _, topicSet := range topics {
		if len(topicSet) > 0 {
			return true
		}
	}
	return false
}

// RetrieveBlockNumberByHash returns the block number for the given block hash
func (ecr *CIDRetriever) RetrieveBlockNumberByHash(tx *sqlx.Tx, blockHash common.Hash) (uint64, error) {
	log.Debug("retrieving block number for block hash ", blockHash.String())
	pgStr := `SELECT CAST(block_number as TEXT) FROM eth.header_cids WHERE block_hash = $1`
	var blockNumberStr string
	if err := tx.Get(&blockNumberStr, pgStr, blockHash.String()); err != nil {
		return 0, err
	}
	return strconv.ParseUint(blockNumberStr, 10, 64)
}

// RetrieveHeaderAndTxCIDsByBlockNumber retrieves header CIDs and their associated tx CIDs by block number
func (ecr *CIDRetriever) RetrieveHeaderAndTxCIDsByBlockNumber(blockNumber int64) ([]HeaderCIDRecord, error) {
	log.Debug("retrieving header cids and tx cids for block number ", blockNumber)

	var headerCIDs []HeaderCIDRecord

	// https://github.com/go-gorm/gorm/issues/4083#issuecomment-778883283
	// Will use join for TransactionCIDs once preload for 1:N is supported.
	err := ecr.gormDB.Preload("TransactionCIDs", func(tx *gorm.DB) *gorm.DB {
		return tx.Select("cid", "tx_hash", "index", "src", "dst", "header_id", "block_number")
	}).Joins("IPLD").Find(&headerCIDs, "header_cids.block_number = ?", blockNumber).Error

	if err != nil {
		log.Error("header cid retrieval error")
		return nil, err
	}

	return headerCIDs, nil
}

// RetrieveHeaderAndTxCIDsByBlockHash retrieves header CID and their associated tx CIDs by block hash (and optionally block number)
func (ecr *CIDRetriever) RetrieveHeaderAndTxCIDsByBlockHash(blockHash common.Hash, blockNumber *big.Int) (HeaderCIDRecord, error) {
	log.Debug("retrieving header cid and tx cids for block hash ", blockHash.String())

	var headerCIDs []HeaderCIDRecord

	conditions := map[string]interface{}{"block_hash": blockHash.String()}
	if blockNumber != nil {
		conditions["header_cids.block_number"] = blockNumber.Int64()
	}

	// https://github.com/go-gorm/gorm/issues/4083#issuecomment-778883283
	// Will use join for TransactionCIDs once preload for 1:N is supported.
	err := ecr.gormDB.Preload("TransactionCIDs", func(tx *gorm.DB) *gorm.DB {
		return tx.Select("cid", "tx_hash", "index", "src", "dst", "header_id", "block_number")
	}).Joins("IPLD").Find(&headerCIDs, conditions).Error

	if err != nil {
		log.Error("header cid retrieval error")
		return HeaderCIDRecord{}, err
	}

	if len(headerCIDs) == 0 {
		return HeaderCIDRecord{}, errHeaderHashNotFound
	} else if len(headerCIDs) > 1 {
		return HeaderCIDRecord{}, errMultipleHeadersForHash
	}

	return headerCIDs[0], nil
}

// RetrieveTxCIDByHash returns the tx for the given tx hash (and optionally block number)
func (ecr *CIDRetriever) RetrieveTxCIDByHash(txHash string, blockNumber *big.Int) (TransactionCIDRecord, error) {
	log.Debug("retrieving tx cid for tx hash ", txHash)

	var txCIDs []TransactionCIDRecord

	var err error
	if blockNumber != nil {
		err = ecr.gormDB.Joins("IPLD").Find(&txCIDs, "tx_hash = ? AND transaction_cids.header_id = (SELECT canonical_header_hash(transaction_cids.block_number)) AND transaction_cids.block_number = ?", txHash, blockNumber.Int64()).Error
	} else {
		err = ecr.gormDB.Joins("IPLD").Find(&txCIDs, "tx_hash = ? AND transaction_cids.header_id = (SELECT canonical_header_hash(transaction_cids.block_number))", txHash).Error
	}
	if err != nil {
		log.Error("tx retrieval error")
		return TransactionCIDRecord{}, err
	}

	if len(txCIDs) == 0 {
		return TransactionCIDRecord{}, errTxHashNotFound
	} else if len(txCIDs) > 1 {
		// a transaction can be part of a only one canonical block
		return TransactionCIDRecord{}, errTxHashInMultipleBlocks
	}

	return txCIDs[0], nil
}
