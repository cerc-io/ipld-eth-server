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

package test_helpers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff/indexer/ipld"
	"github.com/ethereum/go-ethereum/statediff/indexer/models"
	"github.com/ethereum/go-ethereum/statediff/indexer/shared"
	testhelpers "github.com/ethereum/go-ethereum/statediff/test_helpers"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	"github.com/ethereum/go-ethereum/trie"
	blocks "github.com/ipfs/go-block-format"
	"github.com/multiformats/go-multihash"
	log "github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
)

// Test variables
var (
	// block data
	BlockNumber = big.NewInt(1)
	MockHeader  = types.Header{
		Time:        0,
		Number:      new(big.Int).Set(BlockNumber),
		Root:        common.HexToHash("0x0"),
		TxHash:      common.HexToHash("0x0"),
		ReceiptHash: common.HexToHash("0x0"),
		Difficulty:  big.NewInt(5000000),
		Extra:       []byte{},
	}
	MockTransactions, MockReceipts, SenderAddr = createLegacyTransactionsAndReceipts()
	MockUncles                                 = []*types.Header{
		{
			Time:        1,
			Number:      new(big.Int).Add(BlockNumber, big.NewInt(1)),
			Root:        common.HexToHash("0x1"),
			TxHash:      common.HexToHash("0x1"),
			ReceiptHash: common.HexToHash("0x1"),
			Difficulty:  big.NewInt(500001),
			Extra:       []byte{},
		},
		{
			Time:        2,
			Number:      new(big.Int).Add(BlockNumber, big.NewInt(2)),
			Root:        common.HexToHash("0x2"),
			TxHash:      common.HexToHash("0x2"),
			ReceiptHash: common.HexToHash("0x2"),
			Difficulty:  big.NewInt(500002),
			Extra:       []byte{},
		},
	}
	ReceiptsRlp, _   = rlp.EncodeToBytes(MockReceipts)
	MockBlock        = createNewBlock(&MockHeader, MockTransactions, MockUncles, MockReceipts, new(trie.Trie))
	MockHeaderRlp, _ = rlp.EncodeToBytes(MockBlock.Header())
	MockChildHeader  = types.Header{
		Time:        0,
		Number:      new(big.Int).Add(BlockNumber, common.Big1),
		Root:        common.HexToHash("0x0"),
		TxHash:      common.HexToHash("0x0"),
		ReceiptHash: common.HexToHash("0x0"),
		Difficulty:  big.NewInt(5000001),
		Extra:       []byte{},
		ParentHash:  MockBlock.Header().Hash(),
	}
	MockChild            = types.NewBlock(&MockChildHeader, MockTransactions, MockUncles, MockReceipts, new(trie.Trie))
	MockChildRlp, _      = rlp.EncodeToBytes(MockChild.Header())
	Address              = common.HexToAddress("0xaE9BEa628c4Ce503DcFD7E305CaB4e29E7476592")
	AnotherAddress       = common.HexToAddress("0xaE9BEa628c4Ce503DcFD7E305CaB4e29E7476593")
	AnotherAddress1      = common.HexToAddress("0xaE9BEa628c4Ce503DcFD7E305CaB4e29E7476594")
	AnotherAddress2      = common.HexToAddress("0xaE9BEa628c4Ce503DcFD7E305CaB4e29E7476596")
	ContractAddress      = crypto.CreateAddress(SenderAddr, MockTransactions[2].Nonce())
	ContractHash         = crypto.Keccak256Hash(ContractAddress.Bytes()).String()
	MockContractByteCode = []byte{0, 1, 2, 3, 4, 5}
	mockTopic11          = common.HexToHash("0x04")
	mockTopic12          = common.HexToHash("0x06")
	mockTopic21          = common.HexToHash("0x05")
	mockTopic22          = common.HexToHash("0x07")
	mockTopic31          = common.HexToHash("0x08")
	mockTopic41          = common.HexToHash("0x09")
	mockTopic42          = common.HexToHash("0x0a")
	mockTopic43          = common.HexToHash("0x0b")
	mockTopic51          = common.HexToHash("0x0c")
	mockTopic61          = common.HexToHash("0x0d")
	MockLog1             = &types.Log{
		Address:     Address,
		Topics:      []common.Hash{mockTopic11, mockTopic12},
		Data:        []byte{},
		BlockNumber: BlockNumber.Uint64(),
		TxIndex:     0,
		Index:       0,
	}
	MockLog2 = &types.Log{
		Address:     AnotherAddress,
		Topics:      []common.Hash{mockTopic21, mockTopic22},
		Data:        []byte{},
		BlockNumber: BlockNumber.Uint64(),
		TxIndex:     1,
		Index:       1,
	}
	MockLog3 = &types.Log{
		Address:     AnotherAddress1,
		Topics:      []common.Hash{mockTopic31},
		Data:        []byte{},
		BlockNumber: BlockNumber.Uint64(),
		TxIndex:     2,
		Index:       2,
	}

	MockLog4 = &types.Log{
		Address:     AnotherAddress1,
		Topics:      []common.Hash{mockTopic41, mockTopic42, mockTopic43},
		Data:        []byte{},
		BlockNumber: BlockNumber.Uint64(),
		TxIndex:     2,
		Index:       3,
	}
	MockLog5 = &types.Log{
		Address:     AnotherAddress1,
		Topics:      []common.Hash{mockTopic51},
		Data:        []byte{},
		BlockNumber: BlockNumber.Uint64(),
		TxIndex:     2,
		Index:       4,
	}
	MockLog6 = &types.Log{
		Address:     AnotherAddress2,
		Topics:      []common.Hash{mockTopic61},
		Data:        []byte{},
		BlockNumber: BlockNumber.Uint64(),
		TxIndex:     3,
		Index:       5,
	}

	Tx1 = GetTxnRlp(0, MockTransactions)
	Tx2 = GetTxnRlp(1, MockTransactions)
	Tx3 = GetTxnRlp(2, MockTransactions)
	Tx4 = GetTxnRlp(3, MockTransactions)

	rctCIDs, rctIPLDData, _ = eth.GetRctLeafNodeData(MockReceipts)
	HeaderCID, _            = ipld.RawdataToCid(ipld.MEthHeader, MockHeaderRlp, multihash.KECCAK_256)
	HeaderMhKey             = shared.MultihashKeyFromCID(HeaderCID)
	Trx1CID, _              = ipld.RawdataToCid(ipld.MEthTx, Tx1, multihash.KECCAK_256)
	Trx1MhKey               = shared.MultihashKeyFromCID(Trx1CID)
	Trx2CID, _              = ipld.RawdataToCid(ipld.MEthTx, Tx2, multihash.KECCAK_256)
	Trx2MhKey               = shared.MultihashKeyFromCID(Trx2CID)
	Trx3CID, _              = ipld.RawdataToCid(ipld.MEthTx, Tx3, multihash.KECCAK_256)
	Trx3MhKey               = shared.MultihashKeyFromCID(Trx3CID)
	Trx4CID, _              = ipld.RawdataToCid(ipld.MEthTx, Tx4, multihash.KECCAK_256)
	Trx4MhKey               = shared.MultihashKeyFromCID(Trx4CID)
	Rct1CID                 = rctCIDs[0]
	Rct1MhKey               = shared.MultihashKeyFromCID(Rct1CID)
	Rct2CID                 = rctCIDs[1]
	Rct2MhKey               = shared.MultihashKeyFromCID(Rct2CID)
	Rct3CID                 = rctCIDs[2]
	Rct3MhKey               = shared.MultihashKeyFromCID(Rct3CID)
	Rct4CID                 = rctCIDs[3]
	Rct4MhKey               = shared.MultihashKeyFromCID(Rct4CID)
	State1CID, _            = ipld.RawdataToCid(ipld.MEthStateTrie, ContractLeafNode, multihash.KECCAK_256)
	State1MhKey             = shared.MultihashKeyFromCID(State1CID)
	State2CID, _            = ipld.RawdataToCid(ipld.MEthStateTrie, AccountLeafNode, multihash.KECCAK_256)
	State2MhKey             = shared.MultihashKeyFromCID(State2CID)
	StorageCID, _           = ipld.RawdataToCid(ipld.MEthStorageTrie, StorageLeafNode, multihash.KECCAK_256)
	StorageMhKey            = shared.MultihashKeyFromCID(StorageCID)
	Rct1IPLD                = rctIPLDData[0]
	Rct2IPLD                = rctIPLDData[1]
	Rct3IPLD                = rctIPLDData[2]
	Rct4IPLD                = rctIPLDData[3]
	MockTrxMeta             = []models.TxModel{
		{
			CID:    "", // This is empty until we go to publish to ipfs
			MhKey:  "",
			Src:    SenderAddr.Hex(),
			Dst:    Address.String(),
			Index:  0,
			TxHash: MockTransactions[0].Hash().String(),
			Data:   []byte{},
		},
		{
			CID:    "",
			MhKey:  "",
			Src:    SenderAddr.Hex(),
			Dst:    AnotherAddress.String(),
			Index:  1,
			TxHash: MockTransactions[1].Hash().String(),
			Data:   []byte{},
		},
		{
			CID:    "",
			MhKey:  "",
			Src:    SenderAddr.Hex(),
			Dst:    "",
			Index:  2,
			TxHash: MockTransactions[2].Hash().String(),
			Data:   MockContractByteCode,
		},
		{
			CID:    "",
			MhKey:  "",
			Src:    SenderAddr.Hex(),
			Dst:    "",
			Index:  3,
			TxHash: MockTransactions[3].Hash().String(),
			Data:   []byte{},
		},
	}
	MockTrxMetaPostPublsh = []models.TxModel{
		{
			CID:    Trx1CID.String(), // This is empty until we go to publish to ipfs
			MhKey:  Trx1MhKey,
			Src:    SenderAddr.Hex(),
			Dst:    Address.String(),
			Index:  0,
			TxHash: MockTransactions[0].Hash().String(),
			Data:   []byte{},
		},
		{
			CID:    Trx2CID.String(),
			MhKey:  Trx2MhKey,
			Src:    SenderAddr.Hex(),
			Dst:    AnotherAddress.String(),
			Index:  1,
			TxHash: MockTransactions[1].Hash().String(),
			Data:   []byte{},
		},
		{
			CID:    Trx3CID.String(),
			MhKey:  Trx3MhKey,
			Src:    SenderAddr.Hex(),
			Dst:    "",
			Index:  2,
			TxHash: MockTransactions[2].Hash().String(),
			Data:   MockContractByteCode,
		},
		{
			CID:    Trx4CID.String(),
			MhKey:  Trx4MhKey,
			Src:    SenderAddr.Hex(),
			Dst:    AnotherAddress1.String(),
			Index:  3,
			TxHash: MockTransactions[3].Hash().String(),
			Data:   []byte{},
		},
	}
	MockRctMeta = []models.ReceiptModel{
		{
			LeafCID:      "",
			LeafMhKey:    "",
			Contract:     "",
			ContractHash: "",
		},
		{
			LeafCID:      "",
			LeafMhKey:    "",
			Contract:     "",
			ContractHash: "",
		},
		{
			LeafCID:      "",
			LeafMhKey:    "",
			Contract:     ContractAddress.String(),
			ContractHash: ContractHash,
		},
		{
			LeafCID:      "",
			LeafMhKey:    "",
			Contract:     "",
			ContractHash: "",
		},
	}

	MockRctMetaPostPublish = []models.ReceiptModel{
		{
			LeafCID:      Rct1CID.String(),
			LeafMhKey:    Rct1MhKey,
			Contract:     "",
			ContractHash: "",
		},
		{
			LeafCID:      Rct2CID.String(),
			LeafMhKey:    Rct2MhKey,
			Contract:     "",
			ContractHash: "",
		},
		{
			LeafCID:      Rct3CID.String(),
			LeafMhKey:    Rct3MhKey,
			Contract:     ContractAddress.String(),
			ContractHash: ContractHash,
		},
		{
			LeafCID:      Rct4CID.String(),
			LeafMhKey:    Rct4MhKey,
			Contract:     "",
			ContractHash: "",
		},
	}

	// statediff data
	storageLocation    = common.HexToHash("0")
	StorageLeafKey     = crypto.Keccak256Hash(storageLocation[:]).Bytes()
	StorageValue       = crypto.Keccak256([]byte{1, 2, 3, 4, 5})
	StoragePartialPath = common.Hex2Bytes("20290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")
	StorageLeafNode, _ = rlp.EncodeToBytes(&[]interface{}{
		StoragePartialPath,
		StorageValue,
	})

	nonce1             = uint64(1)
	ContractRoot       = "0x821e2556a290c86405f8160a2d662042a431ba456b9db265c79bb837c04be5f0"
	ContractCodeHash   = crypto.Keccak256Hash(MockContractByteCode)
	contractPath       = common.Bytes2Hex([]byte{'\x06'})
	ContractLeafKey    = testhelpers.AddressToLeafKey(ContractAddress)
	ContractAccount, _ = rlp.EncodeToBytes(&types.StateAccount{
		Nonce:    nonce1,
		Balance:  big.NewInt(0),
		CodeHash: ContractCodeHash.Bytes(),
		Root:     common.HexToHash(ContractRoot),
	})
	ContractPartialPath = common.Hex2Bytes("3114658a74d9cc9f7acf2c5cd696c3494d7c344d78bfec3add0d91ec4e8d1c45")
	ContractLeafNode, _ = rlp.EncodeToBytes(&[]interface{}{
		ContractPartialPath,
		ContractAccount,
	})

	nonce0          = uint64(0)
	AccountBalance  = big.NewInt(1000)
	AccountRoot     = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	AccountCodeHash = common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	AccountAddresss = common.HexToAddress("0x0D3ab14BBaD3D99F4203bd7a11aCB94882050E7e")
	AccountLeafKey  = testhelpers.Account2LeafKey
	Account, _      = rlp.EncodeToBytes(&types.StateAccount{
		Nonce:    nonce0,
		Balance:  AccountBalance,
		CodeHash: AccountCodeHash.Bytes(),
		Root:     common.HexToHash(AccountRoot),
	})
	AccountPartialPath = common.Hex2Bytes("3957f3e2f04a0764c3a0491b175f69926da61efbcc8f61fa1455fd2d2b4cdd45")
	AccountLeafNode, _ = rlp.EncodeToBytes(&[]interface{}{
		AccountPartialPath,
		Account,
	})

	MockStateNodes = []sdtypes.StateNode{
		{
			LeafKey:   ContractLeafKey,
			Path:      []byte{'\x06'},
			NodeValue: ContractLeafNode,
			NodeType:  sdtypes.Leaf,
			StorageNodes: []sdtypes.StorageNode{
				{
					Path:      []byte{},
					NodeType:  sdtypes.Leaf,
					LeafKey:   StorageLeafKey,
					NodeValue: StorageLeafNode,
				},
			},
		},
		{
			LeafKey:      AccountLeafKey,
			Path:         []byte{'\x0c'},
			NodeValue:    AccountLeafNode,
			NodeType:     sdtypes.Leaf,
			StorageNodes: []sdtypes.StorageNode{},
		},
	}
	MockStateMetaPostPublish = []models.StateNodeModel{
		{
			CID:      State1CID.String(),
			MhKey:    State1MhKey,
			Path:     []byte{'\x06'},
			NodeType: 2,
			StateKey: common.BytesToHash(ContractLeafKey).Hex(),
		},
		{
			CID:      State2CID.String(),
			MhKey:    State2MhKey,
			Path:     []byte{'\x0c'},
			NodeType: 2,
			StateKey: common.BytesToHash(AccountLeafKey).Hex(),
		},
	}
	MockStorageNodes = map[string][]sdtypes.StorageNode{
		contractPath: {
			{
				LeafKey:   StorageLeafKey,
				NodeValue: StorageLeafNode,
				NodeType:  sdtypes.Leaf,
				Path:      []byte{},
			},
		},
	}

	MockConvertedPayload = eth.ConvertedPayload{
		TotalDifficulty: MockBlock.Difficulty(),
		Block:           MockBlock,
		Receipts:        MockReceipts,
		TxMetaData:      MockTrxMeta,
		ReceiptMetaData: MockRctMeta,
		StorageNodes:    MockStorageNodes,
		StateNodes:      MockStateNodes,
	}
	MockConvertedPayloadForChild = eth.ConvertedPayload{
		TotalDifficulty: MockChild.Difficulty(),
		Block:           MockChild,
		Receipts:        MockReceipts,
		TxMetaData:      MockTrxMeta,
		ReceiptMetaData: MockRctMeta,
		StorageNodes:    MockStorageNodes,
		StateNodes:      MockStateNodes,
	}

	Reward         = shared.CalcEthBlockReward(MockBlock.Header(), MockBlock.Uncles(), MockBlock.Transactions(), MockReceipts)
	MockCIDWrapper = &eth.CIDWrapper{
		BlockNumber: new(big.Int).Set(BlockNumber),
		Header: models.HeaderModel{
			BlockNumber:     "1",
			BlockHash:       MockBlock.Hash().String(),
			ParentHash:      "0x0000000000000000000000000000000000000000000000000000000000000000",
			CID:             HeaderCID.String(),
			MhKey:           HeaderMhKey,
			TotalDifficulty: MockBlock.Difficulty().String(),
			Reward:          Reward.String(),
			StateRoot:       MockBlock.Root().String(),
			RctRoot:         MockBlock.ReceiptHash().String(),
			TxRoot:          MockBlock.TxHash().String(),
			UncleRoot:       MockBlock.UncleHash().String(),
			Bloom:           MockBlock.Bloom().Bytes(),
			Timestamp:       MockBlock.Time(),
			TimesValidated:  1,
			Coinbase:        "0x0000000000000000000000000000000000000000",
		},
		Transactions: MockTrxMetaPostPublsh,
		Receipts:     MockRctMetaPostPublish,
		Uncles:       []models.UncleModel{},
		StateNodes:   MockStateMetaPostPublish,
		StorageNodes: []models.StorageNodeWithStateKeyModel{
			{
				Path:       []byte{},
				CID:        StorageCID.String(),
				MhKey:      StorageMhKey,
				NodeType:   2,
				StateKey:   common.BytesToHash(ContractLeafKey).Hex(),
				StorageKey: common.BytesToHash(StorageLeafKey).Hex(),
			},
		},
	}

	HeaderIPLD, _  = blocks.NewBlockWithCid(MockHeaderRlp, HeaderCID)
	Trx1IPLD, _    = blocks.NewBlockWithCid(Tx1, Trx1CID)
	Trx2IPLD, _    = blocks.NewBlockWithCid(Tx2, Trx2CID)
	Trx3IPLD, _    = blocks.NewBlockWithCid(Tx3, Trx3CID)
	Trx4IPLD, _    = blocks.NewBlockWithCid(Tx4, Trx4CID)
	State1IPLD, _  = blocks.NewBlockWithCid(ContractLeafNode, State1CID)
	State2IPLD, _  = blocks.NewBlockWithCid(AccountLeafNode, State2CID)
	StorageIPLD, _ = blocks.NewBlockWithCid(StorageLeafNode, StorageCID)

	MockIPLDs = eth.IPLDs{
		BlockNumber: new(big.Int).Set(BlockNumber),
		Header: models.IPLDModel{
			Data: HeaderIPLD.RawData(),
			Key:  HeaderIPLD.Cid().String(),
		},
		Transactions: []models.IPLDModel{
			{
				Data: Trx1IPLD.RawData(),
				Key:  Trx1IPLD.Cid().String(),
			},
			{
				Data: Trx2IPLD.RawData(),
				Key:  Trx2IPLD.Cid().String(),
			},
			{
				Data: Trx3IPLD.RawData(),
				Key:  Trx3IPLD.Cid().String(),
			},
			{
				Data: Trx4IPLD.RawData(),
				Key:  Trx4IPLD.Cid().String(),
			},
		},
		Receipts: []models.IPLDModel{
			{
				Data: Rct1IPLD,
				Key:  Rct1CID.String(),
			},
			{
				Data: Rct2IPLD,
				Key:  Rct2CID.String(),
			},
			{
				Data: Rct3IPLD,
				Key:  Rct3CID.String(),
			},
			{
				Data: Rct4IPLD,
				Key:  Rct4CID.String(),
			},
		},
		StateNodes: []eth.StateNode{
			{
				StateLeafKey: common.BytesToHash(ContractLeafKey),
				Type:         sdtypes.Leaf,
				IPLD: models.IPLDModel{
					Data: State1IPLD.RawData(),
					Key:  State1IPLD.Cid().String(),
				},
				Path: []byte{'\x06'},
			},
			{
				StateLeafKey: common.BytesToHash(AccountLeafKey),
				Type:         sdtypes.Leaf,
				IPLD: models.IPLDModel{
					Data: State2IPLD.RawData(),
					Key:  State2IPLD.Cid().String(),
				},
				Path: []byte{'\x0c'},
			},
		},
		StorageNodes: []eth.StorageNode{
			{
				StateLeafKey:   common.BytesToHash(ContractLeafKey),
				StorageLeafKey: common.BytesToHash(StorageLeafKey),
				Type:           sdtypes.Leaf,
				IPLD: models.IPLDModel{
					Data: StorageIPLD.RawData(),
					Key:  StorageIPLD.Cid().String(),
				},
				Path: []byte{},
			},
		},
	}

	LondonBlockNum   = new(big.Int).Add(BlockNumber, big.NewInt(2))
	MockLondonHeader = types.Header{
		Time:       0,
		Number:     LondonBlockNum,
		Root:       common.HexToHash("0x00"),
		Difficulty: big.NewInt(5000000),
		Extra:      []byte{},
		BaseFee:    big.NewInt(params.InitialBaseFee),
	}

	MockLondonTransactions, MockLondonReceipts, _ = createDynamicTransactionsAndReceipts(LondonBlockNum)
	MockLondonBlock                               = createNewBlock(&MockLondonHeader, MockLondonTransactions, nil, MockLondonReceipts, new(trie.Trie))
)

func createNewBlock(header *types.Header, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, hasher types.TrieHasher) *types.Block {
	block := types.NewBlock(header, txs, uncles, receipts, hasher)
	bHash := block.Hash()
	for _, r := range receipts {
		for _, l := range r.Logs {
			l.BlockHash = bHash
		}
	}
	return block
}

// createDynamicTransactionsAndReceipts is a helper function to generate signed mock transactions and mock receipts with mock logs
func createDynamicTransactionsAndReceipts(blockNumber *big.Int) (types.Transactions, types.Receipts, common.Address) {
	// make transactions
	config := params.TestChainConfig
	config.LondonBlock = blockNumber
	trx1 := types.NewTx(&types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     1,
		GasTipCap: big.NewInt(50),
		GasFeeCap: big.NewInt(100),
		Gas:       50,
		To:        &Address,
		Value:     big.NewInt(1000),
		Data:      []byte{},
	})

	transactionSigner := types.MakeSigner(config, blockNumber)
	mockCurve := elliptic.P256()
	mockPrvKey, err := ecdsa.GenerateKey(mockCurve, rand.Reader)
	if err != nil {
		log.Fatal(err.Error())
	}
	signedTrx1, err := types.SignTx(trx1, transactionSigner, mockPrvKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	senderAddr, err := types.Sender(transactionSigner, signedTrx1) // same for both trx
	if err != nil {
		log.Fatal(err.Error())
	}

	// make receipts
	// TODO: Change the receipt type to DynamicFeeTxType once this PR is merged.
	// https://github.com/ethereum/go-ethereum/pull/22806
	mockReceipt1 := &types.Receipt{
		Type:              types.DynamicFeeTxType,
		PostState:         common.HexToHash("0x0").Bytes(),
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 50,
		Logs:              []*types.Log{},
		TxHash:            signedTrx1.Hash(),
	}

	return types.Transactions{signedTrx1}, types.Receipts{mockReceipt1}, senderAddr
}

// createLegacyTransactionsAndReceipts is a helper function to generate signed mock transactions and mock receipts with mock logs
func createLegacyTransactionsAndReceipts() (types.Transactions, types.Receipts, common.Address) {
	// make transactions
	trx1 := types.NewTransaction(0, Address, big.NewInt(1000), 50, big.NewInt(100), []byte{})
	trx2 := types.NewTransaction(1, AnotherAddress, big.NewInt(2000), 100, big.NewInt(200), []byte{})
	trx3 := types.NewContractCreation(2, big.NewInt(1500), 75, big.NewInt(150), MockContractByteCode)
	trx4 := types.NewTransaction(3, AnotherAddress1, big.NewInt(2000), 100, big.NewInt(200), []byte{})
	transactionSigner := types.MakeSigner(params.MainnetChainConfig, new(big.Int).Set(BlockNumber))
	mockCurve := elliptic.P256()
	mockPrvKey, err := ecdsa.GenerateKey(mockCurve, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signedTrx1, err := types.SignTx(trx1, transactionSigner, mockPrvKey)
	if err != nil {
		log.Fatal(err)
	}
	signedTrx2, err := types.SignTx(trx2, transactionSigner, mockPrvKey)
	if err != nil {
		log.Fatal(err)
	}
	signedTrx3, err := types.SignTx(trx3, transactionSigner, mockPrvKey)
	if err != nil {
		log.Fatal(err)
	}
	signedTrx4, err := types.SignTx(trx4, transactionSigner, mockPrvKey)
	if err != nil {
		log.Fatal(err)
	}
	SenderAddr, err := types.Sender(transactionSigner, signedTrx1) // same for both trx
	if err != nil {
		log.Fatal(err)
	}
	// make receipts
	mockReceipt1 := types.NewReceipt(nil, false, 50)

	hash1 := signedTrx1.Hash()
	MockLog1.TxHash = hash1

	mockReceipt1.Logs = []*types.Log{MockLog1}
	mockReceipt1.TxHash = hash1
	mockReceipt1.GasUsed = mockReceipt1.CumulativeGasUsed

	mockReceipt2 := types.NewReceipt(common.HexToHash("0x1").Bytes(), false, 100)
	hash2 := signedTrx2.Hash()
	MockLog2.TxHash = hash2

	mockReceipt2.Logs = []*types.Log{MockLog2}
	mockReceipt2.TxHash = hash2
	mockReceipt2.GasUsed = mockReceipt2.CumulativeGasUsed - mockReceipt1.CumulativeGasUsed

	mockReceipt3 := types.NewReceipt(common.HexToHash("0x2").Bytes(), false, 175)
	mockReceipt3.Logs = []*types.Log{MockLog3, MockLog4, MockLog5}
	mockReceipt3.TxHash = signedTrx3.Hash()
	mockReceipt3.GasUsed = mockReceipt3.CumulativeGasUsed - mockReceipt2.CumulativeGasUsed

	// Receipt with failed status.
	mockReceipt4 := types.NewReceipt(nil, true, 250)
	mockReceipt4.Logs = []*types.Log{MockLog6}
	mockReceipt4.TxHash = signedTrx4.Hash()
	mockReceipt4.GasUsed = mockReceipt4.CumulativeGasUsed - mockReceipt3.CumulativeGasUsed

	return types.Transactions{signedTrx1, signedTrx2, signedTrx3, signedTrx4}, types.Receipts{mockReceipt1, mockReceipt2, mockReceipt3, mockReceipt4}, SenderAddr
}

func GetTxnRlp(num int, txs types.Transactions) []byte {
	buf := new(bytes.Buffer)
	txs.EncodeIndex(num, buf)
	tx := make([]byte, buf.Len())
	copy(tx, buf.Bytes())
	buf.Reset()
	return tx
}

func GetRctRlp(num int, rcts types.Receipts) []byte {
	buf := new(bytes.Buffer)
	rcts.EncodeIndex(num, buf)
	rct := make([]byte, buf.Len())
	copy(rct, buf.Bytes())
	buf.Reset()
	return rct
}
