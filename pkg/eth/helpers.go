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
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"

	"github.com/ethereum/go-ethereum/params"
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

// ChainConfig returns the appropriate ethereum chain config for the provided chain id
func ChainConfig(chainID uint64) (*params.ChainConfig, error) {
	switch chainID {
	case 1:
		return params.MainnetChainConfig, nil
	case 3:
		return params.RopstenChainConfig, nil
	case 4:
		return params.RinkebyChainConfig, nil
	case 5:
		return params.GoerliChainConfig, nil
	default:
		return nil, fmt.Errorf("chain config for chainid %d not available", chainID)
	}
}
