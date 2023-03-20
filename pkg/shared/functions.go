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
	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	dshelp "github.com/ipfs/go-ipfs-ds-help"
	"github.com/jmoiron/sqlx"
)

// HandleZeroAddrPointer will return an emtpy string for a nil address pointer
func HandleZeroAddrPointer(to *common.Address) string {
	if to == nil {
		return ""
	}
	return to.Hex()
}

// HandleZeroAddr will return an empty string for a 0 value address
func HandleZeroAddr(to common.Address) string {
	if to.Hex() == "0x0000000000000000000000000000000000000000" {
		return ""
	}
	return to.Hex()
}

// Rollback sql transaction and log any error
func Rollback(tx *sqlx.Tx) {
	if err := tx.Rollback(); err != nil {
		log.Error(err)
	}
}

// FetchIPLDByMhKeyAndBlockNumber is used to retrieve an ipld from Postgres blockstore with the provided tx, mhkey string and blockNumber
func FetchIPLDByMhKeyAndBlockNumber(tx *sqlx.Tx, mhKey string, blockNumber uint64) ([]byte, error) {
	pgStr := `SELECT data FROM ipld.blocks WHERE key = $1 AND block_number = $2`
	var block []byte
	return block, tx.Get(&block, pgStr, mhKey, blockNumber)
}

// FetchIPLD is used to retrieve an IPLD from Postgres mhkey and blockNumber
func FetchIPLD(db *sqlx.DB, mhKey string, blockNumber uint64) ([]byte, error) {
	pgStr := `SELECT data FROM ipld.blocks WHERE key = $1 AND block_number = $2`
	var block []byte
	return block, db.Get(&block, pgStr, mhKey, blockNumber)
}

// MultihashKeyFromCID converts a cid into a blockstore-prefixed multihash db key string
func MultihashKeyFromCID(c cid.Cid) string {
	dbKey := dshelp.MultihashToDsKey(c.Hash())
	return blockstore.BlockPrefix.String() + dbKey.String()
}

// MultihashKeyFromCIDString converts a cid string into a blockstore-prefixed multihash db key string
func MultihashKeyFromCIDString(c string) (string, error) {
	dc, err := cid.Decode(c)
	if err != nil {
		return "", err
	}
	dbKey := dshelp.MultihashToDsKey(dc.Hash())
	return blockstore.BlockPrefix.String() + dbKey.String(), nil
}
