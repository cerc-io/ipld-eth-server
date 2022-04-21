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

package shared

import (
	"bytes"
	"context"
	"os"
	"strconv"

	. "github.com/onsi/gomega"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/statediff/indexer"
	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql/postgres"
	"github.com/ethereum/go-ethereum/statediff/indexer/interfaces"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/ethereum/go-ethereum/statediff/indexer/node"
	"github.com/jmoiron/sqlx"
)

// IPLDsContainBytes used to check if a list of strings contains a particular string
func IPLDsContainBytes(iplds []models.IPLDModel, b []byte) bool {
	for _, ipld := range iplds {
		if bytes.Equal(ipld.Data, b) {
			return true
		}
	}
	return false
}

// SetupDB is use to setup a db for watcher tests
func SetupDB() *sqlx.DB {
	config := getTestDBConfig()

	db, err := NewDB(config.DbConnectionString(), config)
	Expect(err).NotTo(HaveOccurred())

	return db
}

// TearDownDB is used to tear down the watcher dbs after tests
func TearDownDB(db *sqlx.DB) {
	tx, err := db.Beginx()
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth.header_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth.transaction_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth.receipt_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth.state_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth.storage_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM blocks`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth.log_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(`DELETE FROM eth_meta.watched_addresses`)
	Expect(err).NotTo(HaveOccurred())

	err = tx.Commit()
	Expect(err).NotTo(HaveOccurred())
}

func SetupTestStateDiffIndexer(ctx context.Context, chainConfig *params.ChainConfig, genHash common.Hash) interfaces.StateDiffIndexer {
	testInfo := node.Info{
		GenesisBlock: genHash.String(),
		NetworkID:    "1",
		ID:           "1",
		ClientName:   "geth",
		ChainID:      params.TestChainConfig.ChainID.Uint64(),
	}

	_, stateDiffIndexer, err := indexer.NewStateDiffIndexer(ctx, chainConfig, testInfo, getTestDBConfig())
	Expect(err).NotTo(HaveOccurred())

	return stateDiffIndexer
}

func getTestDBConfig() postgres.Config {
	port, _ := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	return postgres.Config{
		Hostname:     os.Getenv("DATABASE_HOSTNAME"),
		DatabaseName: os.Getenv("DATABASE_NAME"),
		Username:     os.Getenv("DATABASE_USER"),
		Password:     os.Getenv("DATABASE_PASSWORD"),
		Port:         port,
		Driver:       postgres.SQLX,
	}
}
