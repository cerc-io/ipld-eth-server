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

	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/statediff"
)

func ResolveFromNodeType(nodeType statediff.NodeType) int {
	switch nodeType {
	case statediff.Branch:
		return 0
	case statediff.Extension:
		return 1
	case statediff.Leaf:
		return 2
	case statediff.Removed:
		return 3
	default:
		return -1
	}
}

func ResolveToNodeType(nodeType int) statediff.NodeType {
	switch nodeType {
	case 0:
		return statediff.Branch
	case 1:
		return statediff.Extension
	case 2:
		return statediff.Leaf
	case 3:
		return statediff.Removed
	default:
		return statediff.Unknown
	}
}

// ChainConfig returns the appropriate ethereum chain config for the provided chain id
func ChainConfig(chainID uint64) (*params.ChainConfig, error) {
	switch chainID {
	case 1:
		return params.MainnetChainConfig, nil
	case 3:
		return params.TestnetChainConfig, nil // Ropsten
	case 4:
		return params.RinkebyChainConfig, nil
	case 5:
		return params.GoerliChainConfig, nil
	default:
		return nil, fmt.Errorf("chain config for chainid %d not available", chainID)
	}
}
