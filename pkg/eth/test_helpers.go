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

	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql"
	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql/postgres"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/ethereum/go-ethereum/statediff/indexer/node"
	. "github.com/onsi/gomega"
)

func Setup(ctx context.Context, info node.Info) (sql.Database, error) {
	driver, err := postgres.NewSQLXDriver(ctx, getConfig(), info)
	Expect(err).NotTo(HaveOccurred())
	return postgres.NewPostgresDB(driver), nil
}

// TearDownDB is used to tear down the watcher dbs after tests
func TearDownDB(ctx context.Context, db sql.Database) {
	tx, err := db.Begin(ctx)
	Expect(err).NotTo(HaveOccurred())

	_, err = tx.Exec(ctx, `DELETE FROM eth.header_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(ctx, `DELETE FROM eth.transaction_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(ctx, `DELETE FROM eth.receipt_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(ctx, `DELETE FROM eth.state_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(ctx, `DELETE FROM eth.storage_cids`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(ctx, `DELETE FROM blocks`)
	Expect(err).NotTo(HaveOccurred())
	_, err = tx.Exec(ctx, `DELETE FROM eth.log_cids`)
	Expect(err).NotTo(HaveOccurred())

	err = tx.Commit(ctx)
	Expect(err).NotTo(HaveOccurred())
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

func getConfig() postgres.Config {
	return postgres.Config{
		Hostname:     os.Getenv("DATABASE_HOSTNAME"),
		Port:         8077,
		DatabaseName: os.Getenv("DATABASE_NAME"),
		Username:     os.Getenv("DATABASE_USER"),
		Password:     os.Getenv("DATABASE_PASSWORD"),
		Driver:       postgres.PGX,
	}
}
