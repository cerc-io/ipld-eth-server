package events

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Payload packages the data to send to statediff subscriptions
type Payload struct {
	StateDiffRlp []byte `json:"stateDiff"    gencodec:"required"`
}

// StateDiff is the final output structure from the builder
type StateDiff struct {
	BlockNumber     *big.Int      `json:"blockNumber"     gencodec:"required"`
	BlockHash       common.Hash   `json:"blockHash"       gencodec:"required"`
	UpdatedAccounts []AccountDiff `json:"updatedAccounts" gencodec:"required"`
}

// AccountDiff holds the data for a single state diff node
type AccountDiff struct {
	Key     []byte        `json:"key"         gencodec:"required"`
	Value   []byte        `json:"value"       gencodec:"required"`
	Storage []StorageDiff `json:"storage"     gencodec:"required"`
}

// StorageDiff holds the data for a single storage diff node
type StorageDiff struct {
	Key   []byte `json:"key"         gencodec:"required"`
	Value []byte `json:"value"       gencodec:"required"`
}

// JSONPayload notify payload
type JSONPayload struct {
	Node []string `json:"__node__"`
}

type BlockInfoPayload struct {
	BlockNumber string `db:"block_number"`
	BlockHash string `db:"block_hash"`
}

type StateLeafPayload struct {
	StateLeafKey string `db:"state_leaf_key"`
	ID int64 `db:"id"`
	RLPData []byte `db:"data"`
}

type StorageLeafPayload struct {
	StorageLeaf string `db:"storage_leaf_key"`
	RLPData []byte `db:"data"`
}