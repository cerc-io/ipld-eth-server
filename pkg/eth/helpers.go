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
	"math"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

func ResolveToNodeType(nodeType int) sdtypes.NodeType {
	switch nodeType {
	case 0:
		return sdtypes.Branch
	case 1:
		return sdtypes.Extension
	case 2:
		return sdtypes.Leaf
	case 3:
		return sdtypes.Removed
	default:
		return sdtypes.Unknown
	}
}

var pathSteps = []byte{'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f'}

// Return head, stem, and slice byte paths for the given head path and depth
func getPaths(path string, depth int) ([]byte, [][]byte, [][]byte, error) {
	// Convert the head hex path to a decoded byte path
	headPath := common.FromHex(path)

	pathLen := len(headPath)
	if pathLen > 64 { // max path len is 64
		return nil, nil, nil, fmt.Errorf("path length cannot exceed 64; got %d", pathLen)
	}

	maxDepth := 64 - pathLen
	if depth > maxDepth {
		return nil, nil, nil, fmt.Errorf("max depth for path %s is %d; got %d", path, maxDepth, depth)
	}

	// Collect all of the stem paths
	stemPaths := make([][]byte, 0, pathLen)
	for i := 0; i < pathLen; i++ {
		stemPaths = append(stemPaths, headPath[:i])
	}

	// Generate all of the slice paths
	slicePaths := make([][]byte, 0, int(math.Pow(16, float64(depth))))
	makeSlicePaths(headPath, depth, &slicePaths)

	return headPath, stemPaths, slicePaths, nil
}

// iterative function to generate the set of slice paths
func makeSlicePaths(path []byte, depth int, slicePaths *[][]byte) {
	depth--                          // decrement the depth
	nextPaths := make([][]byte, 16)  // slice to hold the next 16 paths
	for i, step := range pathSteps { // iterate through steps
		nextPath := append(path, step) // create next paths by adding steps to current path
		nextPaths[i] = nextPath
		newSlicePaths := append(*slicePaths, nextPath) // add next paths to the collection of all slice paths
		slicePaths = &newSlicePaths
	}

	if depth == 0 { // if depth has reach 0, return
		return
	}
	for _, nextPath := range nextPaths { // if not, then we iterate over the next paths
		makeSlicePaths(nextPath, depth, slicePaths) // and repeat the process for each one
	}
}

// use to return timestamp in milliseconds
func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func populateNodesMap(nodes map[string]string, cids []cid.Cid, iplds [][]byte) error {
	for i, cid := range cids {
		decodedMh, err := multihash.Decode(cid.Hash())
		if err != nil {
			return err
		}

		data := iplds[i]
		hash := crypto.Keccak256Hash(data)
		if !bytes.Equal(hash.Bytes(), decodedMh.Digest) {
			panic("multihash digest should equal keccak of raw data")
		}

		nodes[common.Bytes2Hex(decodedMh.Digest)] = common.Bytes2Hex(data)
	}

	return nil
}
