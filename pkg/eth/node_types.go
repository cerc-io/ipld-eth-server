package eth

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/cerc-io/ipld-eth-statedb/trie_by_cid/trie"
)

// NodeType for explicitly setting type of node
type NodeType string

const (
	Unknown   NodeType = "Unknown"
	Branch    NodeType = "Branch"
	Extension NodeType = "Extension"
	Leaf      NodeType = "Leaf"
	Removed   NodeType = "Removed" // used to represent paths which have been emptied
)

func (n NodeType) Int() int {
	switch n {
	case Branch:
		return 0
	case Extension:
		return 1
	case Leaf:
		return 2
	case Removed:
		return 3
	default:
		return -1
	}
}

// CheckKeyType checks what type of key we have
func CheckKeyType(elements []interface{}) (NodeType, error) {
	if len(elements) > 2 {
		return Branch, nil
	}
	if len(elements) < 2 {
		return Unknown, fmt.Errorf("node cannot be less than two elements in length")
	}
	switch elements[0].([]byte)[0] / 16 {
	case '\x00':
		return Extension, nil
	case '\x01':
		return Extension, nil
	case '\x02':
		return Leaf, nil
	case '\x03':
		return Leaf, nil
	default:
		return Unknown, fmt.Errorf("unknown hex prefix")
	}
}

// StateNode holds the data for a single state diff node
type StateNode struct {
	NodeType     NodeType      `json:"nodeType"        gencodec:"required"`
	Path         []byte        `json:"path"            gencodec:"required"`
	NodeValue    []byte        `json:"value"           gencodec:"required"`
	StorageNodes []StorageNode `json:"storage"`
	LeafKey      []byte        `json:"leafKey"`
}

// StorageNode holds the data for a single storage diff node
type StorageNode struct {
	NodeType  NodeType `json:"nodeType"        gencodec:"required"`
	Path      []byte   `json:"path"            gencodec:"required"`
	NodeValue []byte   `json:"value"           gencodec:"required"`
	LeafKey   []byte   `json:"leafKey"`
}

func ResolveNode(path []byte, node []byte, trieDB *trie.Database) (StateNode, []interface{}, error) {
	var nodeElements []interface{}
	if err := rlp.DecodeBytes(node, &nodeElements); err != nil {
		return StateNode{}, nil, err
	}
	ty, err := CheckKeyType(nodeElements)
	if err != nil {
		return StateNode{}, nil, err
	}

	nodePath := make([]byte, len(path))
	copy(nodePath, path)
	return StateNode{
		NodeType:  ty,
		Path:      nodePath,
		NodeValue: node,
	}, nodeElements, nil
}

// ResolveNodeIt return the state diff node pointed by the iterator.
func ResolveNodeIt(it trie.NodeIterator, trieDB *trie.Database) (StateNode, []interface{}, error) {
	node, err := it.NodeBlob(), it.Error()
	if err != nil {
		return StateNode{}, nil, err
	}
	return ResolveNode(it.Path(), node, trieDB)
}
