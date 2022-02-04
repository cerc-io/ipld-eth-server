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
	"os"
	"strconv"

	. "github.com/onsi/gomega"

	"github.com/ethereum/go-ethereum/statediff/indexer/ipfs"
	"github.com/ethereum/go-ethereum/statediff/indexer/node"
	"github.com/ethereum/go-ethereum/statediff/indexer/postgres"
)

// IPLDsContainBytes used to check if a list of strings contains a particular string
func IPLDsContainBytes(iplds []ipfs.BlockModel, b []byte) bool {
	for _, ipld := range iplds {
		if bytes.Equal(ipld.Data, b) {
			return true
		}
	}
	return false
}

// SetupDB is use to setup a db for watcher tests
func SetupDB() (*postgres.DB, error) {
	port, _ := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	uri := postgres.DbConnectionString(postgres.ConnectionParams{
		User:     os.Getenv("DATABASE_USER"),
		Password: os.Getenv("DATABASE_PASSWORD"),
		Hostname: os.Getenv("DATABASE_HOSTNAME"),
		Name:     os.Getenv("DATABASE_NAME"),
		Port:     port,
	})
	return postgres.NewDB(uri, postgres.ConnectionConfig{}, node.Info{})
}

// TearDownDB is used to tear down the watcher dbs after tests
func TearDownDB(db *postgres.DB) {
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
