package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/statediff"
	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/ipfs"
	"math/big"
)

// CIDWrapper is used to direct fetching of IPLDs from IPFS
// Returned by CIDRetriever
// Passed to IPLDFetcher
type CIDWrapper struct {
	BlockNumber  *big.Int
	Header       eth2.HeaderModel
	Uncles       []eth2.UncleModel
	Transactions []eth2.TxModel
	Receipts     []eth2.ReceiptModel
	StateNodes   []eth2.StateNodeModel
	StorageNodes []eth2.StorageNodeWithStateKeyModel
}

// IPLDs is used to package raw IPLD block data fetched from IPFS and returned by the server
// Returned by IPLDFetcher and ResponseFilterer
type IPLDs struct {
	BlockNumber     *big.Int
	TotalDifficulty *big.Int
	Header          ipfs.BlockModel
	Uncles          []ipfs.BlockModel
	Transactions    []ipfs.BlockModel
	Receipts        []ipfs.BlockModel
	StateNodes      []StateNode
	StorageNodes    []StorageNode
}

type StateNode struct {
	Type         statediff.NodeType
	StateLeafKey common.Hash
	Path         []byte
	IPLD         ipfs.BlockModel
}

type StorageNode struct {
	Type           statediff.NodeType
	StateLeafKey   common.Hash
	StorageLeafKey common.Hash
	Path           []byte
	IPLD           ipfs.BlockModel
}
