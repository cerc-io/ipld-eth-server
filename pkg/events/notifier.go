// VulcanizeDB
// Copyright © 2021 Vulcanize

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

package events

import (
	"encoding/json"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"

	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var (
	getBlockInfoPgStr = `SELECT block_number, block_hash FROM eth.header_cids WHERE id = $1`
	getStateLeafsPgStr = `SELECT state_cids.id, state_leaf_key, data FROM eth.state_cids
						INNER JOIN eth.header_cids ON (state_cids.header_id = header_cids.id)
						INNER JOIN public.blocks ON (state_cids.mh_key = blocks.key)
						WHERE header_cids.id = $1 AND state_leaf_key IS NOT NULL`
	getStorageLeafsPgStr = `SELECT storage_leaf_key, data FROM eth.storage_cids
							INNER JOIN eth.state_cids ON (storage_cids.state_id = state_cids.id)
							INNER JOIN public.blocks ON (storage_cids.mh_key = blocks.key)
							WHERE state_cids.id = $1 AND storage_leaf_key IS NOT NULL`
)

// Notifier listens to inserts on Postgres tables and forwards the data
type Notifier struct {
	db *postgres.DB
	listener *pq.Listener
	failed   chan error
}

// NewNotifier creates a new notifier for given PostgreSQL credentials.
func NewNotifier(db *postgres.DB, channelName string) (*Notifier, error) {
	n := &Notifier{db: db, failed: make(chan error)}

	listener := pq.NewListener(
		db.Config.DbConnectionString(),
		10*time.Second, time.Minute,
		n.callBack)

	if err := listener.Listen(channelName); err != nil {
		listener.Close()
		log.Println("ERROR!:", err)
		return nil, err
	}

	n.listener = listener
	return n, nil
}

func (n *Notifier) SubscribeStateChanges(query ethereum.FilterQuery, payloadChan chan Payload, errChan chan error) {
	outChan := make(chan []byte)
	doneChan := make(chan struct{})
	n.notify(doneChan, outChan, errChan)
	go func() {
		for {
			select {
			case out := <-outChan:
				jsonPayload := new(JSONPayload)
				json.Unmarshal(out, jsonPayload)
				if len(jsonPayload.Node) < 2 {
					log.Warn("pushed JSON payload does not contain expected number of entrie in __node__ array")
					continue
				}
				payload, err := n.getStateChanges(jsonPayload.Node[1])
				if err != nil {
					errChan <- err
					continue
				}
				payloadChan <- *payload
				case <-doneChan:
					return
			}
		}
	}()
}

func (n *Notifier) getStateChanges(headerID string) (*Payload, error) {
	tx, err := n.db.Beginx()
	if err != nil {
		return nil, err
	}
	blockInfo := new(BlockInfoPayload)
	if err := tx.Select(blockInfo, getBlockInfoPgStr, headerID); err != nil {
		shared.Rollback(tx)
		return nil, err
	}
	blockNum := new(big.Int)
	blockNum.SetString(blockInfo.BlockNumber, 10)
	stateLeafPayloads, err := n.getStateLeafs(tx, headerID)
	if err != nil {
		shared.Rollback(tx)
		return nil, err
	}
	stateAccounts := make([]AccountDiff, len(stateLeafPayloads))
	for i, slp := range stateLeafPayloads {
		storageLeafPayloads, err := n.getStorageLeafs(tx, slp.ID)
		if err != nil {
			shared.Rollback(tx)
			return nil, err
		}
		stateAccounts[i] = AccountDiff{
			Key: common.Hex2Bytes(slp.StateLeafKey),
			Value: slp.RLPData,
			Storage:  storageLeafPayloads,
		}
	}
	stateChangePayload := new(StateDiff)
	stateChangePayload.BlockHash = common.HexToHash(blockInfo.BlockHash)
	stateChangePayload.BlockNumber = blockNum
	stateChangePayload.UpdatedAccounts = stateAccounts
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	by, err := rlp.EncodeToBytes(stateChangePayload)
	if err != nil {
		return nil, err
	}
	return &Payload{
		StateDiffRlp: by,
	}, nil
}

func (n *Notifier) getStateLeafs(tx *sqlx.Tx, headerID string) ([]StateLeafPayload, error) {
	rows, err := tx.Queryx(getStateLeafsPgStr, headerID)
	if err != nil {
		return nil, err
	}
	stateLeafPayloads := make([]StateLeafPayload, 0)
	defer rows.Close()
	for rows.Next() {
		stateLeafPayload := new(StateLeafPayload)
		if err := rows.StructScan(stateLeafPayload); err != nil {
			return nil, err
		}
		stateLeafPayloads = append(stateLeafPayloads, *stateLeafPayload)
	}
	if rows.Err() != nil {
		return nil, err
	}
	return stateLeafPayloads, err
}

func (n *Notifier) getStorageLeafs(tx *sqlx.Tx, stateID int64) ([]StorageDiff, error) {
	rows, err := tx.Queryx(getStorageLeafsPgStr, stateID)
	if err != nil {
		return nil, err
	}
	storageLeafPayloads := make([]StorageDiff, 0)
	defer rows.Close()
	for rows.Next() {
		storageLeafPayload := new(StorageLeafPayload)
		if err := rows.StructScan(storageLeafPayload); err != nil {
			return nil, err
		}
		storageLeafPayloads = append(storageLeafPayloads, StorageDiff{
			Key:  common.Hex2Bytes(storageLeafPayload.StorageLeaf),
			Value: storageLeafPayload.RLPData,
		})
	}
	if rows.Err() != nil {
		return nil, err
	}
	return storageLeafPayloads, err
}

// notify is the main loop of the notifier to receive data from
// the database in JSON-FORMAT and send it down the provided channel.
func (n *Notifier) notify(doneChan chan struct{}, outChan chan []byte, errChan chan error) {
	go func() {
		defer close(doneChan)
		for {
			select {
			case e := <-n.listener.Notify:
				if e == nil {
					continue
				}
				outChan <- []byte(e.Extra)
			case err := <-n.failed:
				if err != nil {
					errChan <- err
				}
				return
			case <-time.After(time.Minute):
				if err := n.listener.Ping(); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()
}

// callBack
func (n *Notifier) callBack(event pq.ListenerEventType, err error) {
	if err != nil {
		log.Errorf("listener error: %s\n", err)
	}
	if event == pq.ListenerEventConnectionAttemptFailed {
		n.failed <- err
	}
	if event == pq.ListenerEventDisconnected {
		n.failed <- err
	}
}

// Close closes the notifier.
func (n *Notifier) Close() error {
	return n.listener.Close()
}
