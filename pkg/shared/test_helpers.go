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

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/ipfs"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/node"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/postgres"
)

// SetupDB is use to setup a db for watcher tests
func SetupDB() (*postgres.DB, error) {
	return postgres.NewDB(postgres.Config{
		Hostname: "localhost",
		Name:     "vulcanize_testing",
		Port:     5432,
	}, node.Info{})
}

// ListContainsString used to check if a list of strings contains a particular string
func ListContainsString(sss []string, s string) bool {
	for _, str := range sss {
		if s == str {
			return true
		}
	}
	return false
}

// IPLDsContainBytes used to check if a list of strings contains a particular string
func IPLDsContainBytes(iplds []ipfs.BlockModel, b []byte) bool {
	for _, ipld := range iplds {
		if bytes.Equal(ipld.Data, b) {
			return true
		}
	}
	return false
}

// ListContainsGap used to check if a list of Gaps contains a particular Gap
func ListContainsGap(gapList []eth.DBGap, gap eth.DBGap) bool {
	for _, listGap := range gapList {
		if listGap == gap {
			return true
		}
	}
	return false
}

// TestCID creates a basic CID for testing purposes
func TestCID(b []byte) cid.Cid {
	pref := cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   multihash.KECCAK_256,
		MhLength: -1,
	}
	c, _ := pref.Sum(b)
	return c
}

// PublishMockIPLD writes a mhkey-data pair to the public.blocks table so that test data can FK reference the mhkey
func PublishMockIPLD(db *postgres.DB, mhKey string, mockData []byte) error {
	_, err := db.Exec(`INSERT INTO public.blocks (key, data) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, mhKey, mockData)
	return err
}
