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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/statediff/indexer/ipld"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	dshelp "github.com/ipfs/go-ipfs-ds-help"
	node "github.com/ipfs/go-ipld-format"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
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
		logrus.Error(err)
	}
}

// PublishIPLD is used to insert an ipld into Postgres blockstore with the provided tx
func PublishIPLD(tx *sqlx.Tx, i node.Node) error {
	dbKey := dshelp.MultihashToDsKey(i.Cid().Hash())
	prefixedKey := blockstore.BlockPrefix.String() + dbKey.String()
	raw := i.RawData()
	_, err := tx.Exec(`INSERT INTO public.blocks (key, data) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, prefixedKey, raw)
	return err
}

// FetchIPLD is used to retrieve an ipld from Postgres blockstore with the provided tx and cid string
func FetchIPLD(tx *sqlx.Tx, cid string) ([]byte, error) {
	mhKey, err := MultihashKeyFromCIDString(cid)
	if err != nil {
		return nil, err
	}
	pgStr := `SELECT data FROM public.blocks WHERE key = $1`
	var block []byte
	return block, tx.Get(&block, pgStr, mhKey)
}

// FetchIPLDByMhKey is used to retrieve an ipld from Postgres blockstore with the provided tx and mhkey string
func FetchIPLDByMhKey(tx *sqlx.Tx, mhKey string) ([]byte, error) {
	pgStr := `SELECT data FROM public.blocks WHERE key = $1`
	var block []byte
	return block, tx.Get(&block, pgStr, mhKey)
}

// FetchIPLDByMhKeysAndBlockNumbers is used to retrieve iplds from Postgres blockstore with the provided tx, mhkey strings and blockNumbers
func FetchIPLDsByMhKeys(tx *sqlx.Tx, mhKeys []string) ([]models.IPLDModel, error) {
	var blocks []models.IPLDModel
	pgStr := `SELECT key, data FROM public.blocks WHERE key IN (?)`
	query, args, err := sqlx.In(pgStr, mhKeys)
	if err != nil {
		return blocks, err
	}
	query = tx.Rebind(query)

	return blocks, tx.Select(&blocks, query, args...)
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

// PublishRaw derives a cid from raw bytes and provided codec and multihash type, and writes it to the db tx
func PublishRaw(tx *sqlx.Tx, codec, mh uint64, raw []byte) (string, error) {
	c, err := ipld.RawdataToCid(codec, raw, mh)
	if err != nil {
		return "", err
	}
	dbKey := dshelp.MultihashToDsKey(c.Hash())
	prefixedKey := blockstore.BlockPrefix.String() + dbKey.String()
	_, err = tx.Exec(`INSERT INTO public.blocks (key, data) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, prefixedKey, raw)
	return c.String(), err
}
