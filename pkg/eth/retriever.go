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
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/log"
)

// Retriever is used for fetching
type Retriever struct {
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
	UnclesHash      string
	Bloom           []byte

	// gorm doesn't check if foreign key exists in database.
	// It is required to eager load relations using preload.
	TransactionCIDs []TransactionCIDRecord `gorm:"foreignKey:HeaderID,BlockNumber;references:BlockHash,BlockNumber"`
	IPLD            IPLDModelRecord        `gorm:"foreignKey:CID,BlockNumber;references:Key,BlockNumber"`
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
	IPLD        IPLDModelRecord `gorm:"foreignKey:CID,BlockNumber;references:Key,BlockNumber"`
}

type StateAccountRecord struct {
	Nonce    uint64 `db:"nonce"`
	Balance  string `db:"balance"`
	Root     string `db:"storage_root"`
	CodeHash []byte `db:"code_hash"`
	Removed  bool   `db:"removed"`
}

// TableName overrides the table name used by TransactionCIDRecord
func (TransactionCIDRecord) TableName() string {
	return "eth.transaction_cids"
}

// NewRetriever returns a pointer to a new Retriever which supports the Retriever interface
func NewRetriever(db *sqlx.DB) *Retriever {
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})

	if err != nil {
		log.Error(err)
		return nil
	}

	return &Retriever{
		db:     db,
		gormDB: gormDB,
	}
}

// RetrieveFirstBlockNumber is used to retrieve the first block number in the db
func (r *Retriever) RetrieveFirstBlockNumber() (int64, error) {
	var blockNumber int64
	err := r.db.Get(&blockNumber, "SELECT block_number FROM ipld.blocks ORDER BY block_number ASC LIMIT 1")
	return blockNumber, err
}

// RetrieveLastBlockNumber is used to retrieve the latest block number in the db
func (r *Retriever) RetrieveLastBlockNumber() (int64, error) {
	var blockNumber int64
	err := r.db.Get(&blockNumber, "SELECT block_number FROM ipld.blocks ORDER BY block_number DESC LIMIT 1")
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
func (r *Retriever) RetrieveFilteredGQLLogs(tx *sqlx.Tx, rctFilter ReceiptFilter, blockHash *common.Hash, blockNumber *big.Int) ([]LogResult, error) {
	log.Debug("retrieving log cids for receipt ids with block hash", blockHash.String())
	args := make([]interface{}, 0, 4)
	id := 1
	pgStr := RetrieveFilteredGQLLogs
	args = append(args, blockHash.String())
	id++

	if blockNumber != nil {
		pgStr += ` AND receipt_cids.block_number = $2`
		id++
		args = append(args, blockNumber.Int64())
	}

	pgStr, args = logFilterCondition(&id, pgStr, args, rctFilter)
	pgStr += ` ORDER BY log_cids.block_number, log_cids.index`

	logs := make([]LogResult, 0)
	err := tx.Select(&logs, pgStr, args...)
	if err != nil {
		return nil, err
	}

	return logs, nil
}

// RetrieveFilteredLogsForBlock retrieves and returns all the log CIDs for the block that conform to the provided filter parameters.
func (r *Retriever) RetrieveFilteredLogsForBlock(db *sqlx.DB, rctFilter ReceiptFilter, blockHash *common.Hash) ([]LogResult, error) {
	return r.retrieveFilteredLogs(db, rctFilter, -1, -1, blockHash)
}

// RetrieveFilteredLogsForBlockRange retrieves and returns all the log CIDs for the blocks in the range that conform
// to the provided filter parameters.
func (r *Retriever) RetrieveFilteredLogsForBlockRange(db *sqlx.DB, rctFilter ReceiptFilter, startBlockNumber int64, stopBlockNumber int64) ([]LogResult, error) {
	return r.retrieveFilteredLogs(db, rctFilter, startBlockNumber, stopBlockNumber, nil)
}

// retrieveFilteredLogs retrieves all the log CIDs either for a single block (by hash) or range of blocks (by number) which
// conform to the provided filter parameters.
func (r *Retriever) retrieveFilteredLogs(db *sqlx.DB, rctFilter ReceiptFilter, startBlockNumber int64, stopBlockNumber int64, blockHash *common.Hash) ([]LogResult, error) {
	log.Debug("retrieving log cids for receipt ids")
	args := make([]interface{}, 0, 4)
	var pgStr string
	id := 1
	if blockHash != nil {
		pgStr = RetrieveFilteredLogsSingle
		args = append(args, blockHash.String())
		id++
	} else {
		pgStr = RetrieveFilteredLogsRange
		args = append(args, startBlockNumber)
		id++
		args = append(args, stopBlockNumber)
		id++
	}

	pgStr, args = logFilterCondition(&id, pgStr, args, rctFilter)
	pgStr += ` ORDER BY eth.log_cids.block_number, eth.log_cids.index`

	logs := make([]LogResult, 0)
	err := db.Select(&logs, pgStr, args...)
	if err != nil {
		return nil, err
	}
	// decode logs and extract original contract Data
	for i, log := range logs {
		var buf []interface{}
		r := bytes.NewReader(log.LogLeafData)
		if err := rlp.Decode(r, &buf); err != nil {
			return nil, err
		}
		logs[i].Data = buf[2].([]byte)
	}

	return logs, nil
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
func (r *Retriever) RetrieveBlockNumberByHash(tx *sqlx.Tx, blockHash common.Hash) (uint64, error) {
	log.Debug("retrieving block number for block hash ", blockHash.String())
	pgStr := `SELECT CAST(block_number as TEXT) FROM eth.header_cids WHERE block_hash = $1`
	var blockNumberStr string
	if err := tx.Get(&blockNumberStr, pgStr, blockHash.String()); err != nil {
		return 0, err
	}
	return strconv.ParseUint(blockNumberStr, 10, 64)
}

// RetrieveHeaderAndTxCIDsByBlockNumber retrieves header CIDs and their associated tx CIDs by block number
func (r *Retriever) RetrieveHeaderAndTxCIDsByBlockNumber(blockNumber int64) ([]HeaderCIDRecord, error) {
	log.Debug("retrieving header cids and tx cids for block number ", blockNumber)

	var headerCIDs []HeaderCIDRecord

	// https://github.com/go-gorm/gorm/issues/4083#issuecomment-778883283
	// Will use join for TransactionCIDs once preload for 1:N is supported.
	err := r.gormDB.Preload("TransactionCIDs", func(tx *gorm.DB) *gorm.DB {
		return tx.Select("cid", "tx_hash", "index", "src", "dst", "header_id", "block_number")
	}).Joins("IPLD").Find(&headerCIDs, "header_cids.block_number = ?", blockNumber).Error

	if err != nil {
		log.Error("header cid retrieval error")
		return nil, err
	}

	return headerCIDs, nil
}

// RetrieveHeaderAndTxCIDsByBlockHash retrieves header CID and their associated tx CIDs by block hash (and optionally block number)
func (r *Retriever) RetrieveHeaderAndTxCIDsByBlockHash(blockHash common.Hash, blockNumber *big.Int) (HeaderCIDRecord, error) {
	log.Debug("retrieving header cid and tx cids for block hash ", blockHash.String())

	var headerCIDs []HeaderCIDRecord

	conditions := map[string]interface{}{"block_hash": blockHash.String()}
	if blockNumber != nil {
		conditions["header_cids.block_number"] = blockNumber.Int64()
	}

	// https://github.com/go-gorm/gorm/issues/4083#issuecomment-778883283
	// Will use join for TransactionCIDs once preload for 1:N is supported.
	err := r.gormDB.Preload("TransactionCIDs", func(tx *gorm.DB) *gorm.DB {
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
func (r *Retriever) RetrieveTxCIDByHash(txHash string, blockNumber *big.Int) (TransactionCIDRecord, error) {
	log.Debug("retrieving tx cid for tx hash ", txHash)

	var txCIDs []TransactionCIDRecord

	var err error
	if blockNumber != nil {
		err = r.gormDB.Joins("IPLD").Find(&txCIDs, "tx_hash = ? AND transaction_cids.header_id = (SELECT canonical_header_hash(transaction_cids.block_number)) AND transaction_cids.block_number = ?", txHash, blockNumber.Int64()).Error
	} else {
		err = r.gormDB.Joins("IPLD").Find(&txCIDs, "tx_hash = ? AND transaction_cids.header_id = (SELECT canonical_header_hash(transaction_cids.block_number))", txHash).Error
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

var EmptyNodeValue = make([]byte, common.HashLength)

// RetrieveHeaderByHash returns the cid and rlp bytes for the header corresponding to the provided block hash
func (r *Retriever) RetrieveHeaderByHash(hash common.Hash) (string, []byte, error) {
	headerResult := new(ipldResult)
	return headerResult.CID, headerResult.Data, r.db.Get(headerResult, RetrieveHeaderByHashPgStr, hash.Hex())
}

// RetrieveHeaderByHash2 returns the cid and rlp bytes for the header corresponding to the provided block hash
// using a sqlx.Tx
func (r *Retriever) RetrieveHeaderByHash2(tx *sqlx.Tx, hash common.Hash) (string, []byte, error) {
	headerResult := new(ipldResult)
	return headerResult.CID, headerResult.Data, tx.Get(headerResult, RetrieveHeaderByHashPgStr, hash.Hex())
}

// RetrieveUncles returns the cid and rlp bytes for the uncle list corresponding to the provided block hash, number (of non-omner root block)
func (r *Retriever) RetrieveUncles(tx *sqlx.Tx, hash common.Hash, number uint64) (string, []byte, error) {
	uncleResult := new(ipldResult)
	if err := tx.Get(uncleResult, RetrieveUnclesPgStr, hash.Hex(), number); err != nil {
		return "", nil, err
	}
	return uncleResult.CID, uncleResult.Data, nil
}

// RetrieveUnclesByBlockHash returns the cid and rlp bytes for the uncle list corresponding to the provided block hash (of non-omner root block)
func (r *Retriever) RetrieveUnclesByBlockHash(tx *sqlx.Tx, hash common.Hash) (string, []byte, error) {
	uncleResult := new(ipldResult)
	if err := tx.Get(uncleResult, RetrieveUnclesByBlockHashPgStr, hash.Hex()); err != nil {
		return "", nil, err
	}
	return uncleResult.CID, uncleResult.Data, nil
}

// RetrieveTransactions returns the cids and rlp bytes for the transactions corresponding to the provided block hash, number
func (r *Retriever) RetrieveTransactions(tx *sqlx.Tx, hash common.Hash, number uint64) ([]string, [][]byte, error) {
	txResults := make([]ipldResult, 0)
	if err := tx.Select(&txResults, RetrieveTransactionsPgStr, hash.Hex(), number); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(txResults))
	txs := make([][]byte, len(txResults))
	for i, res := range txResults {
		cids[i] = res.CID
		txs[i] = res.Data
	}
	return cids, txs, nil
}

// RetrieveTransactionsByBlockHash returns the cids and rlp bytes for the transactions corresponding to the provided block hash
func (r *Retriever) RetrieveTransactionsByBlockHash(tx *sqlx.Tx, hash common.Hash) ([]string, [][]byte, error) {
	txResults := make([]ipldResult, 0)
	if err := tx.Select(&txResults, RetrieveTransactionsByBlockHashPgStr, hash.Hex()); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(txResults))
	txs := make([][]byte, len(txResults))
	for i, res := range txResults {
		cids[i] = res.CID
		txs[i] = res.Data
	}
	return cids, txs, nil
}

// DecodeLeafNode decodes the leaf node data
func DecodeLeafNode(node []byte) ([]byte, error) {
	var nodeElements []interface{}
	if err := rlp.DecodeBytes(node, &nodeElements); err != nil {
		return nil, err
	}
	ok, err := IsLeaf(nodeElements)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("expected leaf node but found %v", nodeElements)
	}
	return nodeElements[1].([]byte), nil
}

// RetrieveReceipts returns the cids and rlp bytes for the receipts corresponding to the provided block hash, number.
// cid returned corresponds to the leaf node data which contains the receipt.
func (r *Retriever) RetrieveReceipts(tx *sqlx.Tx, hash common.Hash, number uint64) ([]string, [][]byte, []common.Hash, error) {
	rctResults := make([]ipldResult, 0)
	if err := tx.Select(&rctResults, RetrieveReceiptsPgStr, hash.Hex(), number); err != nil {
		return nil, nil, nil, err
	}
	cids := make([]string, len(rctResults))
	rcts := make([][]byte, len(rctResults))
	txs := make([]common.Hash, len(rctResults))

	for i, res := range rctResults {
		cids[i] = res.CID
		rcts[i] = res.Data
		txs[i] = common.HexToHash(res.TxHash)
	}

	return cids, rcts, txs, nil
}

// RetrieveReceiptsByBlockHash returns the cids and rlp bytes for the receipts corresponding to the provided block hash.
// cid returned corresponds to the leaf node data which contains the receipt.
func (r *Retriever) RetrieveReceiptsByBlockHash(tx *sqlx.Tx, hash common.Hash) ([]string, [][]byte, []common.Hash, error) {
	rctResults := make([]ipldResult, 0)
	if err := tx.Select(&rctResults, RetrieveReceiptsByBlockHashPgStr, hash.Hex()); err != nil {
		return nil, nil, nil, err
	}
	cids := make([]string, len(rctResults))
	rcts := make([][]byte, len(rctResults))
	txs := make([]common.Hash, len(rctResults))

	for i, res := range rctResults {
		cids[i] = res.CID
		nodeVal, err := DecodeLeafNode(res.Data)
		if err != nil {
			return nil, nil, nil, err
		}
		rcts[i] = nodeVal
		txs[i] = common.HexToHash(res.TxHash)
	}

	return cids, rcts, txs, nil
}

// RetrieveAccountByAddressAndBlockHash returns the cid and rlp bytes for the account corresponding to the provided address and block hash
// TODO: ensure this handles deleted accounts appropriately
func (r *Retriever) RetrieveAccountByAddressAndBlockHash(address common.Address, hash common.Hash) (StateAccountRecord, error) {
	var accountResult StateAccountRecord
	leafKey := crypto.Keccak256Hash(address.Bytes())
	if err := r.db.Get(&accountResult, RetrieveAccountByLeafKeyAndBlockHashPgStr, leafKey.Hex(), hash.Hex()); err != nil {
		return StateAccountRecord{}, err
	}

	if accountResult.Removed {
		return StateAccountRecord{}, nil
	}
	return accountResult, nil
}

// RetrieveStorageAtByAddressAndStorageSlotAndBlockHash returns the cid and rlp bytes for the storage value corresponding to the provided address, storage slot, and block hash
func (r *Retriever) RetrieveStorageAtByAddressAndStorageSlotAndBlockHash(address common.Address, key, hash common.Hash) ([]byte, error) {
	var storageResult nodeInfo
	stateLeafKey := crypto.Keccak256Hash(address.Bytes())
	storageHash := crypto.Keccak256Hash(key.Bytes())
	if err := r.db.Get(&storageResult,
		RetrieveStorageLeafByAddressHashAndLeafKeyAndBlockHashPgStr,
		stateLeafKey.Hex(), storageHash.Hex(), hash.Hex()); err != nil {
		return nil, err
	}
	if storageResult.StateLeafRemoved || storageResult.Removed {
		return EmptyNodeValue, nil
	}
	return storageResult.Value, nil
}

// RetrieveStorageAndRLP returns the cid and rlp bytes for the storage value corresponding to the
// provided address, storage slot, and block hash
func (r *Retriever) RetrieveStorageAndRLP(address common.Address, key, hash common.Hash) (string, []byte, error) {
	var storageResult nodeInfo
	stateLeafKey := crypto.Keccak256Hash(address.Bytes())
	storageHash := crypto.Keccak256Hash(key.Bytes())
	if err := r.db.Get(&storageResult,
		RetrieveStorageAndRLPByAddressHashAndLeafKeyAndBlockHashPgStr,
		stateLeafKey.Hex(), storageHash.Hex(), hash.Hex()); err != nil {
		return "", nil, err
	}
	if storageResult.StateLeafRemoved || storageResult.Removed {
		return "", EmptyNodeValue, nil
	}
	return storageResult.CID, storageResult.Data, nil
}
