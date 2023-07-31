package eth

const (
	RetrieveHeaderByHashPgStr = `
SELECT header_cids.cid,
	blocks.data
FROM ipld.blocks,
	eth.header_cids
WHERE header_cids.block_hash = $1
	AND header_cids.canonical
	AND blocks.key = header_cids.cid
	AND blocks.block_number = header_cids.block_number
LIMIT 1
`
	RetrieveUnclesPgStr = `SELECT uncle_cids.cid, data
										FROM eth.uncle_cids
											INNER JOIN eth.header_cids ON (
												uncle_cids.header_id = header_cids.block_hash
												AND uncle_cids.block_number = header_cids.block_number
											)
											INNER JOIN ipld.blocks ON (
												uncle_cids.cid = blocks.key
												AND uncle_cids.block_number = blocks.block_number
											)
										WHERE header_cids.block_hash = $1
										AND header_cids.block_number = $2
										ORDER BY uncle_cids.parent_hash
										LIMIT 1`
	RetrieveUnclesByBlockHashPgStr = `SELECT uncle_cids.cid, data
										FROM eth.uncle_cids
											INNER JOIN eth.header_cids ON (
												uncle_cids.header_id = header_cids.block_hash
												AND uncle_cids.block_number = header_cids.block_number
											)
											INNER JOIN ipld.blocks ON (
												uncle_cids.cid = blocks.key
												AND uncle_cids.block_number = blocks.block_number
											)
										WHERE header_cids.block_hash = $1
										ORDER BY uncle_cids.parent_hash
										LIMIT 1`
	RetrieveTransactionsPgStr = `
SELECT transaction_cids.cid,
	blocks.data
FROM eth.transaction_cids,
	eth.header_cids,
	ipld.blocks
WHERE header_cids.block_hash = $1
    AND header_cids.block_number = $2
	AND header_cids.canonical
	AND transaction_cids.block_number = header_cids.block_number
	AND transaction_cids.header_id = header_cids.block_hash
	AND blocks.block_number = header_cids.block_number
	AND blocks.key = transaction_cids.cid
ORDER BY eth.transaction_cids.index ASC
`
	RetrieveTransactionsByBlockHashPgStr = `
SELECT transaction_cids.cid,
	blocks.data
FROM eth.transaction_cids,
	eth.header_cids,
	ipld.blocks
WHERE header_cids.block_hash = $1
	AND header_cids.canonical
	AND transaction_cids.block_number = header_cids.block_number
	AND transaction_cids.header_id = header_cids.block_hash
	AND blocks.block_number = header_cids.block_number
	AND blocks.key = transaction_cids.cid
ORDER BY eth.transaction_cids.index ASC
`
	RetrieveReceiptsPgStr = `
SELECT receipt_cids.cid,
	blocks.data,
	eth.transaction_cids.tx_hash
FROM eth.receipt_cids,
	eth.transaction_cids,
	eth.header_cids,
	ipld.blocks
WHERE header_cids.block_hash = $1
	AND header_cids.block_number = $2
	AND header_cids.canonical
	AND receipt_cids.block_number = header_cids.block_number
	AND receipt_cids.header_id = header_cids.block_hash
	AND receipt_cids.TX_ID = transaction_cids.TX_HASH
	AND transaction_cids.block_number = header_cids.block_number
	AND transaction_cids.header_id = header_cids.block_hash
	AND blocks.block_number = header_cids.block_number
	AND blocks.key = receipt_cids.cid
ORDER BY eth.transaction_cids.index ASC
`
	RetrieveReceiptsByBlockHashPgStr = `
SELECT receipt_cids.cid,
	blocks.data,
	eth.transaction_cids.tx_hash
FROM eth.receipt_cids,
	eth.transaction_cids,
	eth.header_cids,
	ipld.blocks
WHERE header_cids.block_hash = $1
	AND header_cids.canonical
	AND receipt_cids.block_number = header_cids.block_number
	AND receipt_cids.header_id = header_cids.block_hash
	AND receipt_cids.TX_ID = transaction_cids.TX_HASH
	AND transaction_cids.block_number = header_cids.block_number
	AND transaction_cids.header_id = header_cids.block_hash
	AND blocks.block_number = header_cids.block_number
	AND blocks.key = receipt_cids.cid
ORDER BY eth.transaction_cids.index ASC
`
	RetrieveAccountByLeafKeyAndBlockHashPgStr = `
SELECT state_cids.nonce,
	state_cids.balance,
	state_cids.storage_root,
	state_cids.code_hash,
	state_cids.removed
FROM eth.state_cids,
	eth.header_cids
WHERE state_cids.state_leaf_key = $1
	AND state_cids.block_number <=
		(SELECT block_number
			FROM eth.header_cids
			WHERE block_hash = $2
			LIMIT 1)
	AND header_cids.canonical
	AND state_cids.header_id = header_cids.block_hash
	AND state_cids.block_number = header_cids.block_number
ORDER BY state_cids.block_number DESC
LIMIT 1
`
	RetrieveFilteredGQLLogs = `SELECT CAST(eth.log_cids.block_number as TEXT), eth.log_cids.header_id as block_hash,
			eth.log_cids.cid, eth.log_cids.index, eth.log_cids.rct_id, eth.log_cids.address,
			eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3,
			data, eth.receipt_cids.cid AS rct_cid, eth.receipt_cids.post_status, eth.receipt_cids.tx_id AS tx_hash
				FROM eth.log_cids, eth.receipt_cids, ipld.blocks
				WHERE eth.log_cids.rct_id = receipt_cids.tx_id
				AND eth.log_cids.header_id = receipt_cids.header_id
				AND eth.log_cids.block_number = receipt_cids.block_number
				AND log_cids.cid = blocks.key
				AND log_cids.block_number = blocks.block_number
				AND receipt_cids.header_id = $1`
	RetrieveFilteredLogsRange = `SELECT CAST(eth.log_cids.block_number as TEXT), eth.log_cids.cid, eth.log_cids.index, eth.log_cids.rct_id,
			eth.log_cids.address, eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3,
			eth.transaction_cids.tx_hash, eth.transaction_cids.index as txn_index,
			ipld.blocks.data, eth.receipt_cids.cid AS rct_cid, eth.receipt_cids.post_status, log_cids.header_id AS block_hash
							FROM eth.log_cids, eth.receipt_cids, eth.transaction_cids, ipld.blocks
							WHERE eth.log_cids.block_number >= $1 AND eth.log_cids.block_number <= $2
							AND eth.log_cids.header_id IN (SELECT block_hash from eth.header_cids where eth.header_cids.block_number >= $1 AND eth.header_cids.block_number <= $2 and eth.header_cids.canonical)
							AND eth.transaction_cids.block_number = eth.log_cids.block_number
							AND eth.transaction_cids.header_id = eth.log_cids.header_id
							AND eth.receipt_cids.block_number = eth.log_cids.block_number
							AND eth.receipt_cids.header_id = eth.log_cids.header_id
							AND eth.receipt_cids.tx_id = eth.log_cids.rct_id
							AND eth.receipt_cids.tx_id = eth.transaction_cids.tx_hash
							AND ipld.blocks.block_number = eth.log_cids.block_number
							AND ipld.blocks.key = eth.log_cids.cid`

	RetrieveFilteredLogsSingle = `SELECT CAST(eth.log_cids.block_number as TEXT), eth.log_cids.cid, eth.log_cids.index, eth.log_cids.rct_id,
			eth.log_cids.address, eth.log_cids.topic0, eth.log_cids.topic1, eth.log_cids.topic2, eth.log_cids.topic3,
			eth.transaction_cids.tx_hash, eth.transaction_cids.index as txn_index,
			ipld.blocks.data, eth.receipt_cids.cid AS rct_cid, eth.receipt_cids.post_status, log_cids.header_id AS block_hash
							FROM eth.log_cids, eth.receipt_cids, eth.transaction_cids, ipld.blocks
							WHERE eth.log_cids.header_id = $1
							AND eth.transaction_cids.block_number = eth.log_cids.block_number
							AND eth.transaction_cids.header_id = eth.log_cids.header_id
							AND eth.receipt_cids.block_number = eth.log_cids.block_number
							AND eth.receipt_cids.header_id = eth.log_cids.header_id
							AND eth.receipt_cids.tx_id = eth.log_cids.rct_id
							AND eth.receipt_cids.tx_id = eth.transaction_cids.tx_hash
							AND ipld.blocks.block_number = eth.log_cids.block_number
							AND ipld.blocks.key = eth.log_cids.cid`
	RetrieveStorageLeafByAddressHashAndLeafKeyAndBlockHashPgStr   = `SELECT cid, val, block_number, removed, state_leaf_removed FROM get_storage_at_by_hash($1, $2, $3)`
	RetrieveStorageAndRLPByAddressHashAndLeafKeyAndBlockHashPgStr = `
SELECT cid, val, storage.block_number, removed, state_leaf_removed, data
  FROM get_storage_at_by_hash($1, $2, $3) AS storage
       INNER JOIN ipld.blocks ON (
         storage.cid = blocks.key
         AND storage.block_number = blocks.block_number
       )`
	RetrieveCanonicalBlockHashByNumber = `SELECT block_hash FROM eth.header_cids WHERE block_number = $1 and canonical`
	RetrieveCanonicalHeaderByNumber    = `
SELECT header_cids.cid,
	blocks.data
FROM ipld.blocks,
	eth.header_cids
WHERE header_cids.block_number = $1
	AND header_cids.canonical
	AND blocks.key = header_cids.cid
	AND blocks.block_number = header_cids.block_number
LIMIT 1
`
	RetrieveCanonicalHeaderAndHashByNumber = `
SELECT blocks.data,
       header_cids.block_hash
FROM ipld.blocks,
	eth.header_cids
WHERE header_cids.block_number = $1
	AND header_cids.canonical
	AND blocks.key = header_cids.cid
	AND blocks.block_number = header_cids.block_number
LIMIT 1
`
	RetrieveTD = `SELECT CAST(td as TEXT) FROM eth.header_cids
			WHERE header_cids.block_hash = $1`
	RetrieveRPCTransaction = `
SELECT blocks.data,
	transaction_cids.header_id,
	transaction_cids.block_number,
	transaction_cids.index
FROM eth.transaction_cids,
    ipld.blocks,
	eth.header_cids
WHERE transaction_cids.TX_HASH = $1
	AND header_cids.block_hash = transaction_cids.header_id
	AND header_cids.block_number = transaction_cids.block_number
	AND header_cids.canonical
        AND blocks.key = transaction_cids.cid
	AND blocks.block_number = transaction_cids.block_number
`
	RetrieveCodeHashByLeafKeyAndBlockHash = `
SELECT state_cids.code_hash
FROM eth.state_cids,
	eth.header_cids
WHERE
state_cids.state_leaf_key = $1
	AND state_cids.block_number <=
		(SELECT block_number
			FROM eth.header_cids
			WHERE block_hash = $2
			LIMIT 1)
	AND header_cids.canonical
	AND state_cids.header_id = header_cids.block_hash
	AND state_cids.block_number = header_cids.block_number
ORDER BY state_cids.block_number DESC
LIMIT 1
`
	RetrieveCodeByKey = `SELECT data FROM ipld.blocks WHERE key = $1`
)

type ipldResult struct {
	CID    string `db:"cid"`
	Data   []byte `db:"data"`
	TxHash string `db:"tx_hash"`
}

type nodeInfo struct {
	CID              string `db:"cid"`
	Value            []byte `db:"val"`
	BlockNumber      string `db:"block_number"`
	Data             []byte `db:"data"`
	Removed          bool   `db:"removed"`
	StateLeafRemoved bool   `db:"state_leaf_removed"`
}
