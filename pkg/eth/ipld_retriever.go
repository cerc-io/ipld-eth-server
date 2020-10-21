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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/lib/pq"

	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
)

const (
	RetrieveHeadersByHashesPgStr = `SELECT cid, data FROM eth.header_cids 
								INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
								WHERE block_hash = ANY($1::VARCHAR(66)[])`
	RetrieveHeadersByBlockNumberPgStr = `SELECT cid, data FROM eth.header_cids 
								INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
								WHERE block_number = $1`
	RetrieveHeaderByHashPgStr = `SELECT cid, data FROM eth.header_cids 
								INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
								WHERE block_hash = $1`
	RetrieveUnclesByHashesPgStr = `SELECT cid, data FROM eth.uncle_cids
								INNER JOIN public.blocks ON (uncle_cids.mh_key = blocks.key)
								WHERE block_hash = ANY($1::VARCHAR(66)[])`
	RetrieveUnclesByBlockHashPgStr = `SELECT cid, data FROM eth.uncle_cids, eth.header_cids, public.blocks
										WHERE uncle_cids.header_id = header_cids.id
										AND uncle_cids.mh_key = blocks.key
										AND block_hash = $1`
	RetrieveUnclesByBlockNumberPgStr = `SELECT cid, data FROM eth.uncle_cids, eth.header_cids, public.blocks
										WHERE uncle_cids.header_id = header_cids.id
										AND uncle_cids.mh_key = blocks.key
										AND block_number = $1`
	RetrieveUncleByHashPgStr = `SELECT cid, data FROM eth.uncle_cids
								INNER JOIN public.blocks ON (uncle_cids.mh_key = blocks.key)
								WHERE block_hash = $1`
	RetrieveTransactionsByHashesPgStr = `SELECT cid, data FROM eth.transaction_cids
									INNER JOIN public.blocks ON (transaction_cids.mh_key = blocks.key)
									WHERE tx_hash = ANY($1::VARCHAR(66)[])`
	RetrieveTransactionsByBlockHashPgStr = `SELECT cid, data FROM eth.transaction_cids, eth.header_cids, public.blocks
											WHERE transaction_cids.header_id = header_cids.id
											AND transaction_cids.mh_key = blocks.key
											AND block_hash = $1`
	RetrieveTransactionsByBlockNumberPgStr = `SELECT cid, data FROM eth.transaction_cids, eth.header_cids, public.blocks
											WHERE transaction_cids.header_id = header_cids.id
											AND transaction_cids.mh_key = blocks.key
											AND block_number = $1`
	RetrieveTransactionByHashPgStr = `SELECT cid, data FROM eth.transaction_cids
									INNER JOIN public.blocks ON (transaction_cids.mh_key = blocks.key)
									WHERE tx_hash = $1`
	RetrieveReceiptsByTxHashesPgStr = `SELECT cid, data FROM eth.receipt_cids, eth.transaction_cids, public.blocks
									WHERE receipt_cids.mh_key = blocks.key
									AND receipt_cids.tx_id = transaction_cids.id
									AND tx_hash = ANY($1::VARCHAR(66)[])`
	RetrieveReceiptsByBlockHashPgStr = `SELECT cid, data FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids, public.blocks
										WHERE receipt_cids.tx_id = transaction_cids.id
										AND transaction_cids.header_id = header_cids.id
										AND receipt_cids.mh_key = blocks.key
										AND block_hash = $1`
	RetrieveReceiptsByBlockNumberPgStr = `SELECT cid, data FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids, public.blocks
										WHERE receipt_cids.tx_id = transaction_cids.id
										AND transaction_cids.header_id = header_cids.id
										AND receipt_cids.mh_key = blocks.key
										AND block_number = $1`
	RetrieveReceiptByTxHashPgStr = `SELECT cid, data FROM eth.receipt_cids, eth.transaction_cids, eth.receipt_cids
									WHERE receipt_cids.mh_key = blocks.key
									AND receipt_cids.tx_id = transaction_cids.id
									AND tx_hash = $1`
	RetrieveAccountByLeafKeyAndBlockHashPgStr = `SELECT cid, data FROM eth.state_cids, eth.header_cids, public.blocks
												WHERE state_cids.header_id = header_cids.id
												AND state_cids.mh_key = blocks.key
												AND state_leaf_key = $1
												AND block_hash = $2`
	RetrieveAccountByLeafKeyAndBlockNumberPgStr = `SELECT cid, data FROM eth.state_cids, eth.header_cids, public.blocks
												WHERE state_cids.header_id = header_cids.id
												AND state_cids.mh_key = blocks.key
												AND state_leaf_key = $1
												AND block_number = $2`
)

type ipldResult struct {
	cid  string `db:"cid"`
	data []byte `db:"data"`
}
type IPLDRetriever struct {
	db *postgres.DB
}

func NewIPLDRetriever(db *postgres.DB) *IPLDRetriever {
	return &IPLDRetriever{
		db: db,
	}
}

// RetrieveHeadersByHashes returns the cids and rlp bytes for the headers corresponding to the provided block hashes
func (r *IPLDRetriever) RetrieveHeadersByHashes(hashes []common.Hash) ([]string, [][]byte, error) {
	headerResults := make([]ipldResult, 0)
	hashStrs := make([]string, len(hashes))
	for i, hash := range hashes {
		hashStrs[i] = hash.Hex()
	}
	if err := r.db.Select(&headerResults, RetrieveHeadersByHashesPgStr, pq.Array(hashStrs)); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(headerResults))
	headers := make([][]byte, len(headerResults))
	for i, res := range headerResults {
		cids[i] = res.cid
		headers[i] = res.data
	}
	return cids, headers, nil
}

// RetrieveHeadersByBlockNumber returns the cids and rlp bytes for the headers corresponding to the provided block number
// This can return more than one result since there can be more than one header (non-canonical headers)
func (r *IPLDRetriever) RetrieveHeadersByBlockNumber(number uint64) ([]string, [][]byte, error) {
	headerResults := make([]ipldResult, 0)
	if err := r.db.Select(&headerResults, RetrieveHeadersByBlockNumberPgStr, number); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(headerResults))
	headers := make([][]byte, len(headerResults))
	for i, res := range headerResults {
		cids[i] = res.cid
		headers[i] = res.data
	}
	return cids, headers, nil
}

// RetrieveHeaderByHash returns the cid and rlp bytes for the header corresponding to the provided block hash
func (r *IPLDRetriever) RetrieveHeaderByHash(hash common.Hash) (string, []byte, error) {
	headerResult := new(ipldResult)
	return headerResult.cid, headerResult.data, r.db.Get(headerResult, RetrieveHeaderByHashPgStr, hash.Hex())
}

// RetrieveUnclesByHashes returns the cids and rlp bytes for the uncles corresponding to the provided uncle hashes
func (r *IPLDRetriever) RetrieveUnclesByHashes(hashes []common.Hash) ([]string, [][]byte, error) {
	uncleResults := make([]ipldResult, 0)
	hashStrs := make([]string, len(hashes))
	for i, hash := range hashes {
		hashStrs[i] = hash.Hex()
	}
	if err := r.db.Select(&uncleResults, RetrieveUnclesByHashesPgStr, pq.Array(hashStrs)); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(uncleResults))
	uncles := make([][]byte, len(uncleResults))
	for i, res := range uncleResults {
		cids[i] = res.cid
		uncles[i] = res.data
	}
	return cids, uncles, nil
}

// RetrieveUnclesByBlockHash returns the cids and rlp bytes for the uncles corresponding to the provided block hash (of non-omner root block)
func (r *IPLDRetriever) RetrieveUnclesByBlockHash(hash common.Hash) ([]string, [][]byte, error) {
	uncleResults := make([]ipldResult, 0)
	if err := r.db.Select(&uncleResults, RetrieveUnclesByBlockHashPgStr, hash.Hex()); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(uncleResults))
	uncles := make([][]byte, len(uncleResults))
	for i, res := range uncleResults {
		cids[i] = res.cid
		uncles[i] = res.data
	}
	return cids, uncles, nil
}

// RetrieveUnclesByBlockNumber returns the cids and rlp bytes for the uncles corresponding to the provided block number (of non-omner root block)
func (r *IPLDRetriever) RetrieveUnclesByBlockNumber(number uint64) ([]string, [][]byte, error) {
	uncleResults := make([]ipldResult, 0)
	if err := r.db.Select(&uncleResults, RetrieveUnclesByBlockNumberPgStr, number); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(uncleResults))
	uncles := make([][]byte, len(uncleResults))
	for i, res := range uncleResults {
		cids[i] = res.cid
		uncles[i] = res.data
	}
	return cids, uncles, nil
}

// RetrieveUncleByHash returns the cid and rlp bytes for the uncle corresponding to the provided uncle hash
func (r *IPLDRetriever) RetrieveUncleByHash(hash common.Hash) (string, []byte, error) {
	uncleResult := new(ipldResult)
	return uncleResult.cid, uncleResult.data, r.db.Get(uncleResult, RetrieveUncleByHashPgStr, hash.Hex())
}

// RetrieveTransactionsByHashes returns the cids and rlp bytes for the transactions corresponding to the provided tx hashes
func (r *IPLDRetriever) RetrieveTransactionsByHashes(hashes []common.Hash) ([]string, [][]byte, error) {
	txResults := make([]ipldResult, 0)
	hashStrs := make([]string, len(hashes))
	for i, hash := range hashes {
		hashStrs[i] = hash.Hex()
	}
	if err := r.db.Select(&txResults, RetrieveTransactionsByHashesPgStr, pq.Array(hashStrs)); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(txResults))
	txs := make([][]byte, len(txResults))
	for i, res := range txResults {
		cids[i] = res.cid
		txs[i] = res.data
	}
	return cids, txs, nil
}

// RetrieveTransactionsByBlockHash returns the cids and rlp bytes for the transactions corresponding to the provided block hash
func (r *IPLDRetriever) RetrieveTransactionsByBlockHash(hash common.Hash) ([]string, [][]byte, error) {
	txResults := make([]ipldResult, 0)
	if err := r.db.Select(&txResults, RetrieveTransactionsByBlockHashPgStr, hash.Hex()); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(txResults))
	txs := make([][]byte, len(txResults))
	for i, res := range txResults {
		cids[i] = res.cid
		txs[i] = res.data
	}
	return cids, txs, nil
}

// RetrieveTransactionsByBlockNumber returns the cids and rlp bytes for the transactions corresponding to the provided block number
func (r *IPLDRetriever) RetrieveTransactionsByBlockNumber(number uint64) ([]string, [][]byte, error) {
	txResults := make([]ipldResult, 0)
	if err := r.db.Select(&txResults, RetrieveTransactionsByBlockNumberPgStr, number); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(txResults))
	txs := make([][]byte, len(txResults))
	for i, res := range txResults {
		cids[i] = res.cid
		txs[i] = res.data
	}
	return cids, txs, nil
}

// RetrieveTransactionByTxHash returns the cid and rlp bytes for the transaction corresponding to the provided tx hash
func (r *IPLDRetriever) RetrieveTransactionByTxHash(hash common.Hash) (string, []byte, error) {
	txResult := new(ipldResult)
	return txResult.cid, txResult.data, r.db.Get(txResult, RetrieveTransactionByHashPgStr, hash.Hex())
}

// RetrieveReceiptsByTxHashes returns the cids and rlp bytes for the receipts corresponding to the provided tx hashes
func (r *IPLDRetriever) RetrieveReceiptsByTxHashes(hashes []common.Hash) ([]string, [][]byte, error) {
	rctResults := make([]ipldResult, 0)
	hashStrs := make([]string, len(hashes))
	for i, hash := range hashes {
		hashStrs[i] = hash.Hex()
	}
	if err := r.db.Select(&rctResults, RetrieveReceiptsByTxHashesPgStr, pq.Array(hashStrs)); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(rctResults))
	rcts := make([][]byte, len(rctResults))
	for i, res := range rctResults {
		cids[i] = res.cid
		rcts[i] = res.data
	}
	return cids, rcts, nil
}

// RetrieveReceiptsByBlockHash returns the cids and rlp bytes for the receipts corresponding to the provided block hash
func (r *IPLDRetriever) RetrieveReceiptsByBlockHash(hash common.Hash) ([]string, [][]byte, error) {
	rctResults := make([]ipldResult, 0)
	if err := r.db.Select(&rctResults, RetrieveReceiptsByBlockHashPgStr, hash.Hex()); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(rctResults))
	rcts := make([][]byte, len(rctResults))
	for i, res := range rctResults {
		cids[i] = res.cid
		rcts[i] = res.data
	}
	return cids, rcts, nil
}

// RetrieveReceiptsByBlockNumber returns the cids and rlp bytes for the receipts corresponding to the provided block hash
func (r *IPLDRetriever) RetrieveReceiptsByBlockNumber(number uint64) ([]string, [][]byte, error) {
	rctResults := make([]ipldResult, 0)
	if err := r.db.Select(&rctResults, RetrieveReceiptsByBlockNumberPgStr, number); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(rctResults))
	rcts := make([][]byte, len(rctResults))
	for i, res := range rctResults {
		cids[i] = res.cid
		rcts[i] = res.data
	}
	return cids, rcts, nil
}

// RetrieveReceiptByHash returns the cid and rlp bytes for the receipt corresponding to the provided tx hash
func (r *IPLDRetriever) RetrieveReceiptByHash(hash common.Hash) (string, []byte, error) {
	rctResult := new(ipldResult)
	return rctResult.cid, rctResult.data, r.db.Get(rctResult, RetrieveReceiptByTxHashPgStr, hash.Hex())
}

// RetrieveAccountByAddressAndBlockHash returns the cid and rlp bytes for the account corresponding to the provided address and block hash
func (r *IPLDRetriever) RetrieveAccountByAddressAndBlockHash(address common.Address, hash common.Hash) (string, []byte, error) {
	accountResult := new(ipldResult)
	leafKey := crypto.Keccak256Hash(address.Bytes())
	if err := r.db.Get(accountResult, RetrieveAccountByLeafKeyAndBlockHashPgStr, leafKey.Hex(), hash.Hex()); err != nil {
		return "", nil, err
	}
	var i []interface{}
	if err := rlp.DecodeBytes(accountResult.data, &i); err != nil {
		return "", nil, fmt.Errorf("error decoding state leaf node rlp: %s", err.Error())
	}
	if len(i) != 2 {
		return "", nil, fmt.Errorf("eth IPLDRetriever expected state leaf node rlp to decode into two elements")
	}
	return accountResult.cid, i[1].([]byte), nil
}

// RetrieveAccountByAddressAndBlockNumber returns the cid and rlp bytes for the account corresponding to the provided address and block number
// This can return multiple results if we have two versions of state in the database as the provided height
func (r *IPLDRetriever) RetrieveAccountByAddressAndBlockNumber(address common.Address, number uint64) ([]string, [][]byte, error) {
	accountResults := make([]ipldResult, 0)
	leafKey := crypto.Keccak256Hash(address.Bytes())
	if err := r.db.Get(&accountResults, RetrieveAccountByLeafKeyAndBlockNumberPgStr, leafKey.Hex(), number); err != nil {
		return nil, nil, err
	}
	cids := make([]string, len(accountResults))
	accounts := make([][]byte, len(accountResults))
	for i, res := range accountResults {
		cids[i] = res.cid
		var iface []interface{}
		if err := rlp.DecodeBytes(res.data, &iface); err != nil {
			return nil, nil, fmt.Errorf("error decoding state leaf node rlp: %s", err.Error())
		}
		if len(iface) != 2 {
			return nil, nil, fmt.Errorf("eth IPLDRetriever expected state leaf node rlp to decode into two elements")
		}
		accounts[i] = iface[1].([]byte)
	}
	return cids, accounts, nil
}
