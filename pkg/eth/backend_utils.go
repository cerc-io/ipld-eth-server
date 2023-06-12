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
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	nodeiter "github.com/ethereum/go-ethereum/trie/concurrent_iterator"

	"github.com/cerc-io/ipld-eth-statedb/trie_by_cid/state"
)

var nullHashBytes = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")
var emptyCodeHash = crypto.Keccak256([]byte{})

// RPCMarshalHeader converts the given header to the RPC output.
// This function is eth/internal so we have to make our own version here...
func RPCMarshalHeader(head *types.Header) map[string]interface{} {
	headerMap := map[string]interface{}{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"extraData":        hexutil.Bytes(head.Extra),
		"size":             hexutil.Uint64(head.Size()),
		"gasLimit":         hexutil.Uint64(head.GasLimit),
		"gasUsed":          hexutil.Uint64(head.GasUsed),
		"timestamp":        hexutil.Uint64(head.Time),
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}

	if head.BaseFee != nil {
		headerMap["baseFeePerGas"] = (*hexutil.Big)(head.BaseFee)
	}
	return headerMap
}

// RPCMarshalBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
func RPCMarshalBlock(block *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields := RPCMarshalHeader(block.Header())
	fields["size"] = hexutil.Uint64(block.Size())

	if inclTx {
		formatTx := func(tx *types.Transaction) (interface{}, error) {
			return tx.Hash(), nil
		}
		if fullTx {
			formatTx = func(tx *types.Transaction) (interface{}, error) {
				return NewRPCTransactionFromBlockHash(block, tx.Hash()), nil
			}
		}
		txs := block.Transactions()
		transactions := make([]interface{}, len(txs))
		var err error
		for i, tx := range txs {
			if transactions[i], err = formatTx(tx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}
	uncles := block.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes

	return fields, nil
}

// RPCMarshalBlockWithUncleHashes marshals the block with the provided uncle hashes
func RPCMarshalBlockWithUncleHashes(block *types.Block, uncleHashes []common.Hash, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields := RPCMarshalHeader(block.Header())
	fields["size"] = hexutil.Uint64(block.Size())

	if inclTx {
		formatTx := func(tx *types.Transaction) (interface{}, error) {
			return tx.Hash(), nil
		}
		if fullTx {
			formatTx = func(tx *types.Transaction) (interface{}, error) {
				return NewRPCTransactionFromBlockHash(block, tx.Hash()), nil
			}
		}
		txs := block.Transactions()
		transactions := make([]interface{}, len(txs))
		var err error
		for i, tx := range txs {
			if transactions[i], err = formatTx(tx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}

	fields["uncles"] = uncleHashes
	return fields, nil
}

// NewRPCTransactionFromBlockHash returns a transaction that will serialize to the RPC representation.
func NewRPCTransactionFromBlockHash(b *types.Block, hash common.Hash) *RPCTransaction {
	for idx, tx := range b.Transactions() {
		if tx.Hash() == hash {
			return newRPCTransactionFromBlockIndex(b, uint64(idx))
		}
	}
	return nil
}

// SignerForTx returns an appropriate Signer for this Transaction
func SignerForTx(tx *types.Transaction) types.Signer {
	var signer types.Signer
	if tx.Protected() {
		signer = types.LatestSignerForChainID(tx.ChainId())
	} else {
		signer = types.HomesteadSigner{}
	}
	return signer
}

// NewRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
func NewRPCTransaction(tx *types.Transaction, blockHash common.Hash, blockNumber uint64, index uint64, baseFee *big.Int) *RPCTransaction {
	signer := SignerForTx(tx)
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()
	result := &RPCTransaction{
		From:     from,
		Gas:      hexutil.Uint64(tx.Gas()),
		GasPrice: (*hexutil.Big)(tx.GasPrice()),
		Hash:     tx.Hash(),
		Input:    hexutil.Bytes(tx.Data()), // somehow this is ending up `nil`
		Nonce:    hexutil.Uint64(tx.Nonce()),
		To:       tx.To(),
		Value:    (*hexutil.Big)(tx.Value()),
		Type:     hexutil.Uint64(tx.Type()),
		V:        (*hexutil.Big)(v),
		R:        (*hexutil.Big)(r),
		S:        (*hexutil.Big)(s),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = &blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = (*hexutil.Uint64)(&index)
	}
	switch tx.Type() {
	case types.LegacyTxType:
		// if a legacy transaction has an EIP-155 chain id, include it explicitly
		if id := tx.ChainId(); id.Sign() != 0 {
			result.ChainID = (*hexutil.Big)(id)
		}
	case types.AccessListTxType:
		al := tx.AccessList()
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
	case types.DynamicFeeTxType:
		al := tx.AccessList()
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			// price = min(tip, gasFeeCap - baseFee) + baseFee
			price := math.BigMin(new(big.Int).Add(tx.GasTipCap(), baseFee), tx.GasFeeCap())
			result.GasPrice = (*hexutil.Big)(price)
		} else {
			result.GasPrice = nil
		}
	}
	return result
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

func getBlockAndUncleHashes(cli *rpc.Client, ctx context.Context, method string, args ...interface{}) (*types.Block, []common.Hash, error) {
	var raw json.RawMessage
	err := cli.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, nil, err
	} else if len(raw) == 0 {
		return nil, nil, ethereum.NotFound
	}
	// Decode header and transactions.
	var head *types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		txs[i] = tx.tx
	}
	return types.NewBlockWithHeader(head).WithBody(txs, nil), body.UncleHashes, nil
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a transaction given a block and a transaction index.
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := rlp.EncodeToBytes(txs[index])
	return blob
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(b *types.Block, index uint64) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	return NewRPCTransaction(txs[index], b.Hash(), b.NumberU64(), index, b.BaseFee())
}

func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, fmt.Errorf("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

func getIteratorAtPath(t state.Trie, startKey []byte) (trie.NodeIterator, int64) {
	startTime := makeTimestamp()
	var it trie.NodeIterator

	if len(startKey)%2 != 0 {
		// Zero-pad for odd-length keys, required by HexToKeyBytes()
		startKey = append(startKey, 0)
		it = t.NodeIterator(nodeiter.HexToKeyBytes(startKey))
	} else {
		it = t.NodeIterator(nodeiter.HexToKeyBytes(startKey))
		// Step to the required node (not required if original startKey was odd-length)
		it.Next(true)
	}

	return it, makeTimestamp() - startTime
}

func fillSliceNodeData(
	sdb state.Database,
	nodesMap map[string]string,
	leavesMap map[string]GetSliceResponseAccount,
	node StateNode,
	nodeElements []interface{},
	storage bool,
) (int64, error) {
	// Populate the nodes map
	nodeValHash := crypto.Keccak256Hash(node.NodeValue)
	nodesMap[common.Bytes2Hex(nodeValHash.Bytes())] = common.Bytes2Hex(node.NodeValue)

	// Extract account data if it's a Leaf node
	leafStartTime := makeTimestamp()
	if node.NodeType == Leaf && !storage {
		stateLeafKey, storageRoot, code, err := extractContractAccountInfo(sdb, node, nodeElements)
		if err != nil {
			return 0, fmt.Errorf("GetSlice account lookup error: %s", err.Error())
		}

		if len(code) > 0 {
			// Populate the leaves map
			leavesMap[stateLeafKey] = GetSliceResponseAccount{
				StorageRoot: storageRoot,
				EVMCode:     common.Bytes2Hex(code),
			}
		}
	}

	return makeTimestamp() - leafStartTime, nil
}

func extractContractAccountInfo(sdb state.Database, node StateNode, nodeElements []interface{}) (string, string, []byte, error) {
	var account types.StateAccount
	if err := rlp.DecodeBytes(nodeElements[1].([]byte), &account); err != nil {
		return "", "", nil, fmt.Errorf("error decoding account for leaf node at path %x nerror: %v", node.Path, err)
	}

	if bytes.Equal(account.CodeHash, emptyCodeHash) {
		return "", "", nil, nil
	}

	// Extract state leaf key
	partialPath := trie.CompactToHex(nodeElements[0].([]byte))
	valueNodePath := append(node.Path, partialPath...)
	encodedPath := trie.HexToCompact(valueNodePath)
	leafKey := encodedPath[1:]
	stateLeafKeyString := common.BytesToHash(leafKey).String()

	storageRootString := account.Root.String()

	// Extract codeHash and get code
	codeHash := common.BytesToHash(account.CodeHash)
	codeBytes, err := sdb.ContractCode(codeHash)
	if err != nil {
		return "", "", nil, err
	}

	return stateLeafKeyString, storageRootString, codeBytes, nil
}

// IsLeaf checks if the node we are at is a leaf
func IsLeaf(elements []interface{}) (bool, error) {
	if len(elements) > 2 {
		return false, nil
	}
	if len(elements) < 2 {
		return false, fmt.Errorf("node cannot be less than two elements in length")
	}
	switch elements[0].([]byte)[0] / 16 {
	case '\x00':
		return false, nil
	case '\x01':
		return false, nil
	case '\x02':
		return true, nil
	case '\x03':
		return true, nil
	default:
		return false, fmt.Errorf("unknown hex prefix")
	}
}
