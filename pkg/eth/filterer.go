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
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff/indexer/ipld"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// Filterer interface for substituing mocks in tests
type Filterer interface {
	Filter(filter SubscriptionSettings, payload ConvertedPayload) (*IPLDs, error)
}

// ResponseFilterer satisfies the ResponseFilterer interface for ethereum
type ResponseFilterer struct{}

// NewResponseFilterer creates a new Filterer satisfying the ResponseFilterer interface
func NewResponseFilterer() *ResponseFilterer {
	return &ResponseFilterer{}
}

// Filter is used to filter through eth data to extract and package requested data into a Payload
func (s *ResponseFilterer) Filter(filter SubscriptionSettings, payload ConvertedPayload) (*IPLDs, error) {
	if checkRange(filter.Start.Int64(), filter.End.Int64(), payload.Block.Number().Int64()) {
		response := new(IPLDs)
		response.TotalDifficulty = payload.TotalDifficulty
		if err := s.filterHeaders(filter.HeaderFilter, response, payload); err != nil {
			return nil, err
		}
		txHashes, err := s.filterTransactions(filter.TxFilter, response, payload)
		if err != nil {
			return nil, err
		}
		var filterTxs []common.Hash
		if filter.ReceiptFilter.MatchTxs {
			filterTxs = txHashes
		}
		if err := s.filerReceipts(filter.ReceiptFilter, response, payload, filterTxs); err != nil {
			return nil, err
		}
		if err := s.filterStateAndStorage(filter.StateFilter, filter.StorageFilter, response, payload); err != nil {
			return nil, err
		}
		response.BlockNumber = payload.Block.Number()
		return response, nil
	}
	return nil, nil
}

func (s *ResponseFilterer) filterHeaders(headerFilter HeaderFilter, response *IPLDs, payload ConvertedPayload) error {
	if !headerFilter.Off {
		headerRLP, err := rlp.EncodeToBytes(payload.Block.Header())
		if err != nil {
			return err
		}
		cid, err := ipld.RawdataToCid(ipld.MEthHeader, headerRLP, multihash.KECCAK_256)
		if err != nil {
			return err
		}
		response.Header = models.IPLDModel{
			BlockNumber: payload.Block.Number().String(),
			Data:        headerRLP,
			Key:         cid.String(),
		}
		if headerFilter.Uncles {
			response.Uncles = make([]models.IPLDModel, len(payload.Block.Body().Uncles))
			for i, uncle := range payload.Block.Body().Uncles {
				uncleRlp, err := rlp.EncodeToBytes(uncle)
				if err != nil {
					return err
				}
				cid, err := ipld.RawdataToCid(ipld.MEthHeader, uncleRlp, multihash.KECCAK_256)
				if err != nil {
					return err
				}
				response.Uncles[i] = models.IPLDModel{
					BlockNumber: uncle.Number.String(),
					Data:        uncleRlp,
					Key:         cid.String(),
				}
			}
		}
	}
	return nil
}

func checkRange(start, end, actual int64) bool {
	if (end <= 0 || end >= actual) && start <= actual {
		return true
	}
	return false
}

func (s *ResponseFilterer) filterTransactions(trxFilter TxFilter, response *IPLDs, payload ConvertedPayload) ([]common.Hash, error) {
	var trxHashes []common.Hash
	if !trxFilter.Off {
		trxLen := len(payload.Block.Body().Transactions)
		trxHashes = make([]common.Hash, 0, trxLen)
		response.Transactions = make([]models.IPLDModel, 0, trxLen)
		for i, trx := range payload.Block.Body().Transactions {
			// TODO: check if want corresponding receipt and if we do we must include this transaction
			if checkTransactionAddrs(trxFilter.Src, trxFilter.Dst, payload.TxMetaData[i].Src, payload.TxMetaData[i].Dst) {
				trxBuffer := new(bytes.Buffer)
				if err := trx.EncodeRLP(trxBuffer); err != nil {
					return nil, err
				}
				data := trxBuffer.Bytes()
				cid, err := ipld.RawdataToCid(ipld.MEthTx, data, multihash.KECCAK_256)
				if err != nil {
					return nil, err
				}
				response.Transactions = append(response.Transactions, models.IPLDModel{
					Data: data,
					Key:  cid.String(),
				})
				trxHashes = append(trxHashes, trx.Hash())
			}
		}
	}
	return trxHashes, nil
}

// checkTransactionAddrs returns true if either the transaction src and dst are one of the wanted src and dst addresses
func checkTransactionAddrs(wantedSrc, wantedDst []string, actualSrc, actualDst string) bool {
	// If we aren't filtering for any addresses, every transaction is a go
	if len(wantedDst) == 0 && len(wantedSrc) == 0 {
		return true
	}
	for _, src := range wantedSrc {
		if src == actualSrc {
			return true
		}
	}
	for _, dst := range wantedDst {
		if dst == actualDst {
			return true
		}
	}
	return false
}

func (s *ResponseFilterer) filerReceipts(receiptFilter ReceiptFilter, response *IPLDs, payload ConvertedPayload, trxHashes []common.Hash) error {
	if !receiptFilter.Off {
		response.Receipts = make([]models.IPLDModel, 0, len(payload.Receipts))
		rctLeafCID, rctIPLDData, err := GetRctLeafNodeData(payload.Receipts)
		if err != nil {
			return err
		}

		for idx, receipt := range payload.Receipts {
			// topics is always length 4
			topics := make([][]string, 4)
			contracts := make([]string, len(receipt.Logs))
			for _, l := range receipt.Logs {
				contracts = append(contracts, l.Address.String())
				for idx, t := range l.Topics {
					topics[idx] = append(topics[idx], t.String())
				}
			}

			// TODO: Verify this filter logic.
			if checkReceipts(receipt, receiptFilter.Topics, topics, receiptFilter.LogAddresses, contracts, trxHashes) {
				response.Receipts = append(response.Receipts, models.IPLDModel{
					BlockNumber: payload.Block.Number().String(),
					Data:        rctIPLDData[idx],
					Key:         rctLeafCID[idx].String(),
				})
			}
		}
	}
	return nil
}

func checkReceipts(rct *types.Receipt, wantedTopics, actualTopics [][]string, wantedAddresses []string, actualAddresses []string, wantedTrxHashes []common.Hash) bool {
	// If we aren't filtering for any topics, contracts, or corresponding trxs then all receipts are a go
	if len(wantedTopics) == 0 && len(wantedAddresses) == 0 && len(wantedTrxHashes) == 0 {
		return true
	}
	// Keep receipts that are from watched txs
	for _, wantedTrxHash := range wantedTrxHashes {
		if bytes.Equal(wantedTrxHash.Bytes(), rct.TxHash.Bytes()) {
			return true
		}
	}
	// If there are no wanted contract addresses, we keep all receipts that match the topic filter
	if len(wantedAddresses) == 0 {
		if match := filterMatch(wantedTopics, actualTopics); match == true {
			return true
		}
	}
	// If there are wanted contract addresses to filter on
	for _, wantedAddr := range wantedAddresses {
		// and this is an address of interest
		for _, actualAddr := range actualAddresses {
			if wantedAddr == actualAddr {
				// we keep the receipt if it matches on the topic filter
				if match := filterMatch(wantedTopics, actualTopics); match == true {
					return true
				}
			}
		}
	}
	return false
}

// filterMatch returns true if the actualTopics conform to the wantedTopics filter
func filterMatch(wantedTopics, actualTopics [][]string) bool {
	// actualTopics should always be length 4, but the members can be nil slices
	matches := 0
	for i, actualTopicSet := range actualTopics {
		if i < len(wantedTopics) && len(wantedTopics[i]) > 0 {
			// If we have topics in this filter slot, count as a match if one of the topics matches
			matches += slicesShareString(actualTopicSet, wantedTopics[i])
		} else {
			// Filter slot is either empty or doesn't exist => not matching any topics at this slot => counts as a match
			matches++
		}
	}
	if matches == 4 {
		return true
	}
	return false
}

// returns 1 if the two slices have a string in common, 0 if they do not
func slicesShareString(slice1, slice2 []string) int {
	for _, str1 := range slice1 {
		for _, str2 := range slice2 {
			if str1 == str2 {
				return 1
			}
		}
	}
	return 0
}

// filterStateAndStorage filters state and storage nodes into the response according to the provided filters
func (s *ResponseFilterer) filterStateAndStorage(stateFilter StateFilter, storageFilter StorageFilter, response *IPLDs, payload ConvertedPayload) error {
	response.StateNodes = make([]StateNode, 0, len(payload.StateNodes))
	response.StorageNodes = make([]StorageNode, 0)
	stateAddressFilters := make([]common.Hash, len(stateFilter.Addresses))
	for i, addr := range stateFilter.Addresses {
		stateAddressFilters[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes())
	}
	storageAddressFilters := make([]common.Hash, len(storageFilter.Addresses))
	for i, addr := range storageFilter.Addresses {
		storageAddressFilters[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes())
	}
	storageKeyFilters := make([]common.Hash, len(storageFilter.StorageKeys))
	for i, store := range storageFilter.StorageKeys {
		storageKeyFilters[i] = common.HexToHash(store)
	}
	for _, stateNode := range payload.StateNodes {
		if !stateFilter.Off && checkNodeKeys(stateAddressFilters, stateNode.LeafKey) {
			if stateNode.NodeType == sdtypes.Leaf || stateFilter.IntermediateNodes {
				cid, err := ipld.RawdataToCid(ipld.MEthStateTrie, stateNode.NodeValue, multihash.KECCAK_256)
				if err != nil {
					return err
				}
				response.StateNodes = append(response.StateNodes, StateNode{
					StateLeafKey: common.BytesToHash(stateNode.LeafKey),
					Path:         stateNode.Path,
					IPLD: models.IPLDModel{
						BlockNumber: payload.Block.Number().String(),
						Data:        stateNode.NodeValue,
						Key:         cid.String(),
					},
					Type: stateNode.NodeType,
				})
			}
		}
		if !storageFilter.Off && checkNodeKeys(storageAddressFilters, stateNode.LeafKey) {
			for _, storageNode := range payload.StorageNodes[common.Bytes2Hex(stateNode.Path)] {
				if checkNodeKeys(storageKeyFilters, storageNode.LeafKey) {
					cid, err := ipld.RawdataToCid(ipld.MEthStorageTrie, storageNode.NodeValue, multihash.KECCAK_256)
					if err != nil {
						return err
					}
					response.StorageNodes = append(response.StorageNodes, StorageNode{
						StateLeafKey:   common.BytesToHash(stateNode.LeafKey),
						StorageLeafKey: common.BytesToHash(storageNode.LeafKey),
						IPLD: models.IPLDModel{
							BlockNumber: payload.Block.Number().String(),
							Data:        storageNode.NodeValue,
							Key:         cid.String(),
						},
						Type: storageNode.NodeType,
						Path: storageNode.Path,
					})
				}
			}
		}
	}
	return nil
}

func checkNodeKeys(wantedKeys []common.Hash, actualKey []byte) bool {
	// If we aren't filtering for any specific keys, all nodes are a go
	if len(wantedKeys) == 0 {
		return true
	}
	for _, key := range wantedKeys {
		if bytes.Equal(key.Bytes(), actualKey) {
			return true
		}
	}
	return false
}

// GetRctLeafNodeData converts the receipts to receipt trie and returns the receipt leaf node IPLD data and
// corresponding CIDs
func GetRctLeafNodeData(rcts types.Receipts) ([]cid.Cid, [][]byte, error) {
	receiptTrie := ipld.NewRctTrie()
	for idx, rct := range rcts {
		ethRct, err := ipld.NewReceipt(rct)
		if err != nil {
			return nil, nil, err
		}
		if err = receiptTrie.Add(idx, ethRct.RawData()); err != nil {
			return nil, nil, err
		}
	}

	rctLeafNodes, keys, err := receiptTrie.GetLeafNodes()
	if err != nil {
		return nil, nil, err
	}

	ethRctleafNodeCids := make([]cid.Cid, len(rctLeafNodes))
	ethRctleafNodeData := make([][]byte, len(rctLeafNodes))
	for i, rln := range rctLeafNodes {
		var idx uint

		r := bytes.NewReader(keys[i].TrieKey)
		err = rlp.Decode(r, &idx)
		if err != nil {
			return nil, nil, err
		}

		ethRctleafNodeCids[idx] = rln.Cid()
		ethRctleafNodeData[idx] = rln.RawData()
	}

	return ethRctleafNodeCids, ethRctleafNodeData, nil
}
