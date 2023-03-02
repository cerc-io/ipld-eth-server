// VulcanizeDB
// Copyright © 2020 Vulcanize

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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff/indexer/ipld"
	"github.com/ethereum/go-ethereum/statediff/test_helpers"
	"github.com/ipfs/go-cid"
)

// Test variables
var (
	Testdb          = rawdb.NewMemoryDatabase()
	TestBankKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	TestBankAddress = crypto.PubkeyToAddress(TestBankKey.PublicKey) //0x71562b71999873DB5b286dF957af199Ec94617F7
	TestBankFunds   = big.NewInt(100000000)
	Genesis         = test_helpers.GenesisBlockForTesting(Testdb, TestBankAddress, TestBankFunds)

	Account1Key, _       = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	Account2Key, _       = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	Account1Addr         = crypto.PubkeyToAddress(Account1Key.PublicKey) //0x703c4b2bD70c169f5717101CaeE543299Fc946C7
	Account2Addr         = crypto.PubkeyToAddress(Account2Key.PublicKey) //0x0D3ab14BBaD3D99F4203bd7a11aCB94882050E7e
	DeploymentTxData     = common.Hex2Bytes("608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600180819055506101e2806100676000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806343d726d61461004657806365f3c31a1461005057806373d4a13a1461007e575b600080fd5b61004e61009c565b005b61007c6004803603602081101561006657600080fd5b810190808035906020019092919050505061017b565b005b610086610185565b6040518082815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610141576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602281526020018061018c6022913960400191505060405180910390fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b8060018190555050565b6001548156fe4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6e2ea265627a7a723158205ba91466129f45285f53176d805117208c231ec6343d7896790e6fc4165b802b64736f6c63430005110032")
	ContractCode         = common.Hex2Bytes("608060405234801561001057600080fd5b50600436106100415760003560e01c806343d726d61461004657806365f3c31a1461005057806373d4a13a1461007e575b600080fd5b61004e61009c565b005b61007c6004803603602081101561006657600080fd5b810190808035906020019092919050505061017b565b005b610086610185565b6040518082815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610141576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602281526020018061018c6022913960400191505060405180910390fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b8060018190555050565b6001548156fe4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6e2ea265627a7a723158205ba91466129f45285f53176d805117208c231ec6343d7896790e6fc4165b802b64736f6c63430005110032")
	CodeHash             = crypto.Keccak256Hash(ContractCode)
	ContractAddr         common.Address
	IndexZero            = "0000000000000000000000000000000000000000000000000000000000000000"
	IndexOne             = "0000000000000000000000000000000000000000000000000000000000000001"
	ContractSlotPosition = common.FromHex(IndexOne)
	ContractSlotKeyHash  = crypto.Keccak256Hash(ContractSlotPosition)
	MiningReward         = big.NewInt(2000000000000000000)
)

/* test function signatures
put function sig: 65f3c31a
close function sig: 43d726d6
data function sig: 73d4a13a
*/

// MakeChain creates a chain of n blocks starting at and including parent.
// the returned hash chain is ordered head->parent.
func MakeChain(n int, parent *types.Block, chainGen func(int, *core.BlockGen)) ([]*types.Block, []types.Receipts, *core.BlockChain) {
	config := params.TestChainConfig
	config.LondonBlock = big.NewInt(100)
	blocks, receipts := core.GenerateChain(config, parent, ethash.NewFaker(), Testdb, n, chainGen)
	chain, _ := core.NewBlockChain(Testdb, nil, params.TestChainConfig, ethash.NewFaker(), vm.Config{}, nil, nil)
	return append([]*types.Block{parent}, blocks...), receipts, chain
}

func TestChainGen(i int, block *core.BlockGen) {
	signer := types.HomesteadSigner{}
	switch i {
	case 0:
		// In block 1, the test bank sends account #1 some ether.
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), Account1Addr, big.NewInt(10000), params.TxGas, nil, nil), signer, TestBankKey)
		block.AddTx(tx)
	case 1:
		// In block 2, the test bank sends some more ether to account #1.
		// Account1Addr passes it on to account #2.
		// Account1Addr creates a test contract.
		tx1, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), Account1Addr, big.NewInt(1000), params.TxGas, nil, nil), signer, TestBankKey)
		nonce := block.TxNonce(Account1Addr)
		tx2, _ := types.SignTx(types.NewTransaction(nonce, Account2Addr, big.NewInt(1000), params.TxGas, nil, nil), signer, Account1Key)
		nonce++
		tx3, _ := types.SignTx(types.NewContractCreation(nonce, big.NewInt(0), 1000000, big.NewInt(0), DeploymentTxData), signer, Account1Key)
		ContractAddr = crypto.CreateAddress(Account1Addr, nonce)
		block.AddTx(tx1)
		block.AddTx(tx2)
		block.AddTx(tx3)
	case 2:
		block.SetCoinbase(Account2Addr)
		data := common.Hex2Bytes("65F3C31A0000000000000000000000000000000000000000000000000000000000000003")
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	case 3:
		block.SetCoinbase(Account2Addr)
		data := common.Hex2Bytes("65F3C31A0000000000000000000000000000000000000000000000000000000000000009")
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	case 4:
		block.SetCoinbase(Account1Addr)
		data := common.Hex2Bytes("65F3C31A0000000000000000000000000000000000000000000000000000000000000000")
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	}
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
