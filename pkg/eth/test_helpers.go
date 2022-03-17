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
	"context"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/statediff/indexer"
	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql/postgres"
	"github.com/ethereum/go-ethereum/statediff/indexer/interfaces"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/ethereum/go-ethereum/statediff/indexer/node"
	. "github.com/onsi/gomega"
)

func SetupTestStateDiffIndexer(ctx context.Context, chainConfig *params.ChainConfig, genHash common.Hash) interfaces.StateDiffIndexer {
	testInfo := node.Info{
		GenesisBlock: genHash.String(),
		NetworkID:    "1",
		ID:           "1",
		ClientName:   "geth",
		ChainID:      params.TestChainConfig.ChainID.Uint64(),
	}

	stateDiffIndexer, err := indexer.NewStateDiffIndexer(ctx, chainConfig, testInfo, getTestDBConfig())
	Expect(err).NotTo(HaveOccurred())

	return stateDiffIndexer
}

// TxModelsContainsCID used to check if a list of TxModels contains a specific cid string
func TxModelsContainsCID(txs []models.TxModel, cid string) bool {
	for _, tx := range txs {
		if tx.CID == cid {
			return true
		}
	}
	return false
}

// ReceiptModelsContainsCID used to check if a list of ReceiptModel contains a specific cid string
func ReceiptModelsContainsCID(rcts []models.ReceiptModel, cid string) bool {
	for _, rct := range rcts {
		if rct.LeafCID == cid {
			return true
		}
	}
	return false
}

func getTestDBConfig() postgres.Config {
	port, _ := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	return postgres.Config{
		Hostname:     os.Getenv("DATABASE_HOSTNAME"),
		DatabaseName: os.Getenv("DATABASE_NAME"),
		Username:     os.Getenv("DATABASE_USER"),
		Password:     os.Getenv("DATABASE_PASSWORD"),
		Port:         port,
		Driver:       postgres.PGX,
	}
}
