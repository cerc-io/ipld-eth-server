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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/jmoiron/sqlx"
	"github.com/multiformats/go-multihash"

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/ipfs/ipld"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/postgres"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/shared"
)

// IPLDPublisherAndIndexer satisfies the IPLDPublisher interface for ethereum
// It interfaces directly with the public.blocks table of PG-IPFS rather than going through an ipfs intermediary
// It publishes and indexes IPLDs together in a single sqlx.Tx
type IPLDPublisherAndIndexer struct {
	indexer *CIDIndexer
}

// NewIPLDPublisherAndIndexer creates a pointer to a new IPLDPublisherAndIndexer which satisfies the IPLDPublisher interface
func NewIPLDPublisherAndIndexer(db *postgres.DB) *IPLDPublisherAndIndexer {
	return &IPLDPublisherAndIndexer{
		indexer: NewCIDIndexer(db),
	}
}

// Publish publishes an IPLDPayload to IPFS and returns the corresponding CIDPayload
func (pub *IPLDPublisherAndIndexer) Publish(payload shared.ConvertedData) (shared.CIDsForIndexing, error) {
	ipldPayload, ok := payload.(ConvertedPayload)
	if !ok {
		return nil, fmt.Errorf("eth IPLDPublisherAndIndexer expected payload type %T got %T", ConvertedPayload{}, payload)
	}
	// Generate the iplds
	headerNode, uncleNodes, txNodes, txTrieNodes, rctNodes, rctTrieNodes, err := ipld.FromBlockAndReceipts(ipldPayload.Block, ipldPayload.Receipts)
	if err != nil {
		return nil, err
	}

	// Begin new db tx
	tx, err := pub.indexer.db.Beginx()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(tx)
		} else {
			err = tx.Commit()
		}
	}()

	// Publish trie nodes
	for _, node := range txTrieNodes {
		if err := shared.PublishIPLD(tx, node); err != nil {
			return nil, err
		}
	}
	for _, node := range rctTrieNodes {
		if err := shared.PublishIPLD(tx, node); err != nil {
			return nil, err
		}
	}

	// Publish and index header
	if err := shared.PublishIPLD(tx, headerNode); err != nil {
		return nil, err
	}
	reward := CalcEthBlockReward(ipldPayload.Block.Header(), ipldPayload.Block.Uncles(), ipldPayload.Block.Transactions(), ipldPayload.Receipts)
	header := HeaderModel{
		CID:             headerNode.Cid().String(),
		MhKey:           shared.MultihashKeyFromCID(headerNode.Cid()),
		ParentHash:      ipldPayload.Block.ParentHash().String(),
		BlockNumber:     ipldPayload.Block.Number().String(),
		BlockHash:       ipldPayload.Block.Hash().String(),
		TotalDifficulty: ipldPayload.TotalDifficulty.String(),
		Reward:          reward.String(),
		Bloom:           ipldPayload.Block.Bloom().Bytes(),
		StateRoot:       ipldPayload.Block.Root().String(),
		RctRoot:         ipldPayload.Block.ReceiptHash().String(),
		TxRoot:          ipldPayload.Block.TxHash().String(),
		UncleRoot:       ipldPayload.Block.UncleHash().String(),
		Timestamp:       ipldPayload.Block.Time(),
	}
	headerID, err := pub.indexer.indexHeaderCID(tx, header)
	if err != nil {
		return nil, err
	}

	// Publish and index uncles
	for _, uncleNode := range uncleNodes {
		if err := shared.PublishIPLD(tx, uncleNode); err != nil {
			return nil, err
		}
		uncleReward := CalcUncleMinerReward(ipldPayload.Block.Number().Int64(), uncleNode.Number.Int64())
		uncle := UncleModel{
			CID:        uncleNode.Cid().String(),
			MhKey:      shared.MultihashKeyFromCID(uncleNode.Cid()),
			ParentHash: uncleNode.ParentHash.String(),
			BlockHash:  uncleNode.Hash().String(),
			Reward:     uncleReward.String(),
		}
		if err := pub.indexer.indexUncleCID(tx, uncle, headerID); err != nil {
			return nil, err
		}
	}

	// Publish and index txs and receipts
	for i, txNode := range txNodes {
		if err := shared.PublishIPLD(tx, txNode); err != nil {
			return nil, err
		}
		rctNode := rctNodes[i]
		if err := shared.PublishIPLD(tx, rctNode); err != nil {
			return nil, err
		}
		txModel := ipldPayload.TxMetaData[i]
		txModel.CID = txNode.Cid().String()
		txModel.MhKey = shared.MultihashKeyFromCID(txNode.Cid())
		txID, err := pub.indexer.indexTransactionCID(tx, txModel, headerID)
		if err != nil {
			return nil, err
		}
		if txModel.Deployment {
			if _, err = shared.PublishRaw(tx, ipld.MEthStorageTrie, multihash.KECCAK_256, txModel.Data); err != nil {
				return nil, err
			}
		}
		rctModel := ipldPayload.ReceiptMetaData[i]
		rctModel.CID = rctNode.Cid().String()
		rctModel.MhKey = shared.MultihashKeyFromCID(rctNode.Cid())
		if err := pub.indexer.indexReceiptCID(tx, rctModel, txID); err != nil {
			return nil, err
		}
	}

	// Publish and index state and storage
	err = pub.publishAndIndexStateAndStorage(tx, ipldPayload, headerID)

	// This IPLDPublisher does both publishing and indexing, we do not need to pass anything forward to the indexer
	return nil, err // return err variable explicitly so that we return the err = tx.Commit() assignment in the defer
}

func (pub *IPLDPublisherAndIndexer) publishAndIndexStateAndStorage(tx *sqlx.Tx, ipldPayload ConvertedPayload, headerID int64) error {
	// Publish and index state and storage
	for _, stateNode := range ipldPayload.StateNodes {
		stateCIDStr, err := shared.PublishRaw(tx, ipld.MEthStateTrie, multihash.KECCAK_256, stateNode.Value)
		if err != nil {
			return err
		}
		mhKey, _ := shared.MultihashKeyFromCIDString(stateCIDStr)
		stateModel := StateNodeModel{
			Path:     stateNode.Path,
			StateKey: stateNode.LeafKey.String(),
			CID:      stateCIDStr,
			MhKey:    mhKey,
			NodeType: ResolveFromNodeType(stateNode.Type),
		}
		stateID, err := pub.indexer.indexStateCID(tx, stateModel, headerID)
		if err != nil {
			return err
		}
		// If we have a leaf, decode and index the account data and any associated storage diffs
		if stateNode.Type == statediff.Leaf {
			var i []interface{}
			if err := rlp.DecodeBytes(stateNode.Value, &i); err != nil {
				return err
			}
			if len(i) != 2 {
				return fmt.Errorf("eth IPLDPublisherAndIndexer expected state leaf node rlp to decode into two elements")
			}
			var account state.Account
			if err := rlp.DecodeBytes(i[1].([]byte), &account); err != nil {
				return err
			}
			accountModel := StateAccountModel{
				Balance:     account.Balance.String(),
				Nonce:       account.Nonce,
				CodeHash:    account.CodeHash,
				StorageRoot: account.Root.String(),
			}
			if err := pub.indexer.indexStateAccount(tx, accountModel, stateID); err != nil {
				return err
			}
			for _, storageNode := range ipldPayload.StorageNodes[common.Bytes2Hex(stateNode.Path)] {
				storageCIDStr, err := shared.PublishRaw(tx, ipld.MEthStorageTrie, multihash.KECCAK_256, storageNode.Value)
				if err != nil {
					return err
				}
				mhKey, _ := shared.MultihashKeyFromCIDString(storageCIDStr)
				storageModel := StorageNodeModel{
					Path:       storageNode.Path,
					StorageKey: storageNode.LeafKey.Hex(),
					CID:        storageCIDStr,
					MhKey:      mhKey,
					NodeType:   ResolveFromNodeType(storageNode.Type),
				}
				if err := pub.indexer.indexStorageCID(tx, storageModel, stateID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Index satisfies the shared.CIDIndexer interface
func (pub *IPLDPublisherAndIndexer) Index(cids shared.CIDsForIndexing) error {
	return nil
}
