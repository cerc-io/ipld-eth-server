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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	"github.com/sirupsen/logrus"
)

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
type RPCTransaction struct {
	BlockHash        *common.Hash      `json:"blockHash"`
	BlockNumber      *hexutil.Big      `json:"blockNumber"`
	From             common.Address    `json:"from"`
	Gas              hexutil.Uint64    `json:"gas"`
	GasPrice         *hexutil.Big      `json:"gasPrice"`
	GasFeeCap        *hexutil.Big      `json:"maxFeePerGas,omitempty"`
	GasTipCap        *hexutil.Big      `json:"maxPriorityFeePerGas,omitempty"`
	Hash             common.Hash       `json:"hash"`
	Input            hexutil.Bytes     `json:"input"`
	Nonce            hexutil.Uint64    `json:"nonce"`
	To               *common.Address   `json:"to"`
	TransactionIndex *hexutil.Uint64   `json:"transactionIndex"`
	Value            *hexutil.Big      `json:"value"`
	Type             hexutil.Uint64    `json:"type"`
	Accesses         *types.AccessList `json:"accessList,omitempty"`
	ChainID          *hexutil.Big      `json:"chainId,omitempty"`
	V                *hexutil.Big      `json:"v"`
	R                *hexutil.Big      `json:"r"`
	S                *hexutil.Big      `json:"s"`
}

// RPCReceipt represents a receipt that will serialize to the RPC representation of a receipt
type RPCReceipt struct {
	BlockHash        *common.Hash    `json:"blockHash"`
	BlockNumber      *hexutil.Big    `json:"blockNumber"`
	TransactionHash  *common.Hash    `json:"transactionHash"`
	TransactionIndex *hexutil.Uint64 `json:"transactionIndex"`
	From             common.Address  `json:"from"`
	To               *common.Address `json:"to"`
	GasUsed          hexutil.Uint64  `json:"gasUsed"`
	CumulativeGsUsed hexutil.Uint64  `json:"cumulativeGasUsed"`
	ContractAddress  *common.Address `json:"contractAddress"`
	Logs             []*types.Log    `json:"logs"`
	Bloom            types.Bloom     `json:"logsBloom"`
	Root             []byte          `json:"root"`
	Status           uint64          `json:"status"`
}

// AccountResult struct for GetProof
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

// StorageResult for GetProof
type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From                 *common.Address   `json:"from"`
	To                   *common.Address   `json:"to"`
	Gas                  *hexutil.Uint64   `json:"gas"`
	GasPrice             *hexutil.Big      `json:"gasPrice"`
	MaxFeePerGas         *hexutil.Big      `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big      `json:"maxPriorityFeePerGas"`
	Value                *hexutil.Big      `json:"value"`
	Data                 *hexutil.Bytes    `json:"data"`
	AccessList           *types.AccessList `json:"accessList,omitempty"`
	Input                *hexutil.Bytes    `json:"input"`
}

// from retrieves the transaction sender address.
func (arg *CallArgs) from() common.Address {
	if arg.From == nil {
		return common.Address{}
	}
	return *arg.From
}

// data retrieves the transaction calldata. Input field is preferred.
func (arg *CallArgs) data() []byte {
	if arg.Input != nil {
		return *arg.Input
	}
	if arg.Data != nil {
		return *arg.Data
	}
	return nil
}

// ToMessage converts the transaction arguments to the Message type used by the
// core evm. This method is used in calls and traces that do not require a real
// live transaction.
func (arg *CallArgs) ToMessage(globalGasCap uint64, baseFee *big.Int) (types.Message, error) {
	// Reject invalid combinations of pre- and post-1559 fee styles
	if arg.GasPrice != nil && (arg.MaxFeePerGas != nil || arg.MaxPriorityFeePerGas != nil) {
		return types.Message{}, errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
	}
	// Set sender address or use zero address if none specified.
	addr := arg.from()

	// Set default gas & gas price if none were set
	gas := globalGasCap
	if gas == 0 {
		gas = uint64(math.MaxUint64 / 2)
	}
	if arg.Gas != nil {
		gas = uint64(*arg.Gas)
	}
	if globalGasCap != 0 && globalGasCap < gas {
		logrus.Warn("Caller gas above allowance, capping", "requested", gas, "cap", globalGasCap)
		gas = globalGasCap
	}
	var (
		gasPrice  *big.Int
		gasFeeCap *big.Int
		gasTipCap *big.Int
	)
	if baseFee == nil {
		// If there's no basefee, then it must be a non-1559 execution
		gasPrice = new(big.Int)
		if arg.GasPrice != nil {
			gasPrice = arg.GasPrice.ToInt()
		}
		gasFeeCap, gasTipCap = gasPrice, gasPrice
	} else {
		// A basefee is provided, necessitating 1559-type execution
		if arg.GasPrice != nil {
			// User specified the legacy gas field, convert to 1559 gas typing
			gasPrice = arg.GasPrice.ToInt()
			gasFeeCap, gasTipCap = gasPrice, gasPrice
		} else {
			// User specified 1559 gas feilds (or none), use those
			gasFeeCap = new(big.Int)
			if arg.MaxFeePerGas != nil {
				gasFeeCap = arg.MaxFeePerGas.ToInt()
			}
			gasTipCap = new(big.Int)
			if arg.MaxPriorityFeePerGas != nil {
				gasTipCap = arg.MaxPriorityFeePerGas.ToInt()
			}
			// Backfill the legacy gasPrice for EVM execution, unless we're all zeroes
			gasPrice = new(big.Int)
			if gasFeeCap.BitLen() > 0 || gasTipCap.BitLen() > 0 {
				gasPrice = math.BigMin(new(big.Int).Add(gasTipCap, baseFee), gasFeeCap)
			}
		}
	}
	value := new(big.Int)
	if arg.Value != nil {
		value = arg.Value.ToInt()
	}
	data := arg.data()
	var accessList types.AccessList
	if arg.AccessList != nil {
		accessList = *arg.AccessList
	}
	msg := types.NewMessage(addr, arg.To, 0, value, gas, gasPrice, gasFeeCap, gasTipCap, data, accessList, true)
	return msg, nil
}

// IPLDs is used to package raw IPLD block data fetched from IPFS and returned by the server
// Returned by IPLDFetcher and ResponseFilterer
type IPLDs struct {
	BlockNumber     *big.Int
	TotalDifficulty *big.Int
	Header          models.IPLDModel
	Uncles          []models.IPLDModel
	Transactions    []models.IPLDModel
	Receipts        []models.IPLDModel
	StateNodes      []StateNode
	StorageNodes    []StorageNode
}

type StateNode struct {
	Type         sdtypes.NodeType
	StateLeafKey common.Hash
	Path         []byte
	IPLD         models.IPLDModel
}

type StorageNode struct {
	Type           sdtypes.NodeType
	StateLeafKey   common.Hash
	StorageLeafKey common.Hash
	Path           []byte
	IPLD           models.IPLDModel
}

// CIDWrapper is used to direct fetching of IPLDs from IPFS
// Returned by CIDRetriever
// Passed to IPLDFetcher
type CIDWrapper struct {
	BlockNumber  *big.Int
	Header       models.HeaderModel
	Uncles       []models.UncleModel
	Transactions []models.TxModel
	Receipts     []models.ReceiptModel
	StateNodes   []models.StateNodeModel
	StorageNodes []models.StorageNodeWithStateKeyModel
}

// ConvertedPayload is a custom type which packages raw ETH data for publishing to IPFS and filtering to subscribers
// Returned by PayloadConverter
// Passed to IPLDPublisher and ResponseFilterer
type ConvertedPayload struct {
	TotalDifficulty *big.Int
	Block           *types.Block
	TxMetaData      []models.TxModel
	Receipts        types.Receipts
	ReceiptMetaData []models.ReceiptModel
	StateNodes      []sdtypes.StateNode
	StorageNodes    map[string][]sdtypes.StorageNode
}

// LogResult represent a log.
type LogResult struct {
	LeafCID     string `db:"leaf_cid"`
	ReceiptID   string `db:"rct_id"`
	Address     string `db:"address"`
	Index       int64  `db:"index"`
	Data        []byte `db:"log_data"`
	Topic0      string `db:"topic0"`
	Topic1      string `db:"topic1"`
	Topic2      string `db:"topic2"`
	Topic3      string `db:"topic3"`
	LogLeafData []byte `db:"data"`
	RctCID      string `db:"cid"`
	RctStatus   uint64 `db:"post_status"`
	BlockNumber string `db:"block_number"`
	BlockHash   string `db:"block_hash"`
	TxnIndex    int64  `db:"txn_index"`
	TxHash      string `db:"tx_hash"`
}

// GetSliceResponse holds response for the eth_getSlice method
type GetSliceResponse struct {
	SliceID   string                             `json:"sliceId"`
	MetaData  GetSliceResponseMetadata           `json:"metadata"`
	TrieNodes GetSliceResponseTrieNodes          `json:"trieNodes"`
	Leaves    map[string]GetSliceResponseAccount `json:"leaves"` // key: Keccak256Hash(address) in hex (leafKey)
}

func (sr *GetSliceResponse) init(path string, depth int, root common.Hash) {
	sr.SliceID = fmt.Sprintf("%s-%d-%s", path, depth, root.String())
	sr.MetaData = GetSliceResponseMetadata{
		NodeStats: make(map[string]string, 0),
		TimeStats: make(map[string]string, 0),
	}
	sr.Leaves = make(map[string]GetSliceResponseAccount)
	sr.TrieNodes = GetSliceResponseTrieNodes{
		Stem:  make(map[string]string),
		Head:  make(map[string]string),
		Slice: make(map[string]string),
	}
}

func (sr *GetSliceResponse) populateMetaData(metaData metaDataFields) {
	sr.MetaData.NodeStats["00-stem-and-head-nodes"] = strconv.Itoa(len(sr.TrieNodes.Stem) + len(sr.TrieNodes.Head))
	sr.MetaData.NodeStats["01-max-depth"] = strconv.Itoa(metaData.maxDepth)
	sr.MetaData.NodeStats["02-total-trie-nodes"] = strconv.Itoa(len(sr.TrieNodes.Stem) + len(sr.TrieNodes.Head) + len(sr.TrieNodes.Slice))
	sr.MetaData.NodeStats["03-leaves"] = strconv.Itoa(metaData.leafCount)
	sr.MetaData.NodeStats["04-smart-contracts"] = strconv.Itoa(len(sr.Leaves))

	sr.MetaData.TimeStats["00-trie-loading"] = strconv.FormatInt(metaData.trieLoadingTime, 10)
	sr.MetaData.TimeStats["01-fetch-stem-keys"] = strconv.FormatInt(metaData.stemNodesFetchTime, 10)
	sr.MetaData.TimeStats["02-fetch-slice-keys"] = strconv.FormatInt(metaData.sliceNodesFetchTime, 10)
	sr.MetaData.TimeStats["03-fetch-leaves-info"] = strconv.FormatInt(metaData.leavesFetchTime, 10)
}

type GetSliceResponseMetadata struct {
	TimeStats map[string]string `json:"timeStats"` // stem, state, storage (one by one)
	NodeStats map[string]string `json:"nodeStats"` // total, leaves, smart contracts
}

type GetSliceResponseTrieNodes struct {
	Stem  map[string]string `json:"stem"` // key: Keccak256Hash(data) in hex, value: trie node data in hex
	Head  map[string]string `json:"head"`
	Slice map[string]string `json:"sliceNodes"`
}

type GetSliceResponseAccount struct {
	StorageRoot string `json:"storageRoot"`
	EVMCode     string `json:"evmCode"`
}

type metaDataFields struct {
	maxDepth            int
	leafCount           int
	trieLoadingTime     int64
	stemNodesFetchTime  int64
	sliceNodesFetchTime int64
	leavesFetchTime     int64
}
