package mocks

import (
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// Test variables
var (
	EvenLeafFlag = []byte{byte(2) << 4}
	MockBlockNumber  = big.NewInt(rand.Int63())
	BlockHash    = "0xfa40fbe2d98d98b3363a778d52f2bcd29d6790b9b3f3cab2b167fd12d3550f73"
	NullCodeHash = crypto.Keccak256Hash([]byte{})
	StoragePath  = common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").Bytes()
	StorageKey   = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000001").Bytes()
	MockStorageValue = common.Hex2Bytes("0x03")
	NullHash     = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")

	Testdb          = rawdb.NewMemoryDatabase()
	TestBankKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	TestBankAddress = crypto.PubkeyToAddress(TestBankKey.PublicKey) //0x71562b71999873DB5b286dF957af199Ec94617F7
	BankLeafKey     = AddressToLeafKey(TestBankAddress)
	TestBankFunds   = big.NewInt(100000000)
	Genesis         = core.GenesisBlockForTesting(Testdb, TestBankAddress, TestBankFunds)

	Account1Key, _  = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	Account2Key, _  = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	Account1Addr    = crypto.PubkeyToAddress(Account1Key.PublicKey) //0x703c4b2bD70c169f5717101CaeE543299Fc946C7
	Account2Addr    = crypto.PubkeyToAddress(Account2Key.PublicKey) //0x0D3ab14BBaD3D99F4203bd7a11aCB94882050E7e
	Account1LeafKey = AddressToLeafKey(Account1Addr)
	Account2LeafKey = AddressToLeafKey(Account2Addr)
	ContractCode    = common.Hex2Bytes("608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506040518060200160405280600160ff16815250600190600161007492919061007a565b506100e4565b82606481019282156100ae579160200282015b828111156100ad578251829060ff1690559160200191906001019061008d565b5b5090506100bb91906100bf565b5090565b6100e191905b808211156100dd5760008160009055506001016100c5565b5090565b90565b610294806100f36000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806343d726d61461005157806360cd26851461005b578063c16431b91461009d578063f0ba8440146100d5575b600080fd5b610059610117565b005b6100876004803603602081101561007157600080fd5b81019080803590602001909291905050506101f6565b6040518082815260200191505060405180910390f35b6100d3600480360360408110156100b357600080fd5b81019080803590602001909291908035906020019092919050505061020e565b005b610101600480360360208110156100eb57600080fd5b8101908080359060200190929190505050610225565b6040518082815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101bc576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602281526020018061023e6022913960400191505060405180910390fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b60006001826064811061020557fe5b01549050919050565b806001836064811061021c57fe5b01819055505050565b6001816064811061023257fe5b01600091509050548156fe4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6e2ea265627a7a72315820965c55d5aacd556fdc2807cef18b41da28c73ba7a04927a2234f617033285c5e64736f6c63430005110032")
	ContractAddr    common.Address

	EmptyRootNode, _  = rlp.EncodeToBytes([]byte{})
	EmptyContractRoot = crypto.Keccak256Hash(EmptyRootNode)
)

/* test contract
pragma solidity ^0.5.10;

contract test {
    address payable owner;

    modifier onlyOwner {
        require(
            msg.sender == owner,
            "Only owner can call this function."
        );
        _;
    }

    uint256[100] public data;

	constructor() public {
	    owner = msg.sender;
		data = [1];
	}

    function Put(uint256 addr, uint256 value) public {
        data[addr] = value;
    }

	function Get(uint256 addr) public view returns(uint256) {
		return data[addr];
	}

    function close() public onlyOwner { //onlyOwner is custom modifier
        selfdestruct(owner);  // `owner` is the owners address
    }
}
*/

/* test ABI
[
	{
		"inputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "addr",
				"type": "uint256"
			}
		],
		"name": "Get",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "addr",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "Put",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [],
		"name": "close",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "data",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
*/

/* test compiler output
{
	"linkReferences": {},
	"object": "608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506040518060200160405280600160ff16815250600190600161007492919061007a565b506100e4565b82606481019282156100ae579160200282015b828111156100ad578251829060ff1690559160200191906001019061008d565b5b5090506100bb91906100bf565b5090565b6100e191905b808211156100dd5760008160009055506001016100c5565b5090565b90565b610294806100f36000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806343d726d61461005157806360cd26851461005b578063c16431b91461009d578063f0ba8440146100d5575b600080fd5b610059610117565b005b6100876004803603602081101561007157600080fd5b81019080803590602001909291905050506101f6565b6040518082815260200191505060405180910390f35b6100d3600480360360408110156100b357600080fd5b81019080803590602001909291908035906020019092919050505061020e565b005b610101600480360360208110156100eb57600080fd5b8101908080359060200190929190505050610225565b6040518082815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101bc576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602281526020018061023e6022913960400191505060405180910390fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b60006001826064811061020557fe5b01549050919050565b806001836064811061021c57fe5b01819055505050565b6001816064811061023257fe5b01600091509050548156fe4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6e2ea265627a7a72315820965c55d5aacd556fdc2807cef18b41da28c73ba7a04927a2234f617033285c5e64736f6c63430005110032",
	"opcodes": "PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP CALLER PUSH1 0x0 DUP1 PUSH2 0x100 EXP DUP2 SLOAD DUP2 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF MUL NOT AND SWAP1 DUP4 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND MUL OR SWAP1 SSTORE POP PUSH1 0x40 MLOAD DUP1 PUSH1 0x20 ADD PUSH1 0x40 MSTORE DUP1 PUSH1 0x1 PUSH1 0xFF AND DUP2 MSTORE POP PUSH1 0x1 SWAP1 PUSH1 0x1 PUSH2 0x74 SWAP3 SWAP2 SWAP1 PUSH2 0x7A JUMP JUMPDEST POP PUSH2 0xE4 JUMP JUMPDEST DUP3 PUSH1 0x64 DUP2 ADD SWAP3 DUP3 ISZERO PUSH2 0xAE JUMPI SWAP2 PUSH1 0x20 MUL DUP3 ADD JUMPDEST DUP3 DUP2 GT ISZERO PUSH2 0xAD JUMPI DUP3 MLOAD DUP3 SWAP1 PUSH1 0xFF AND SWAP1 SSTORE SWAP2 PUSH1 0x20 ADD SWAP2 SWAP1 PUSH1 0x1 ADD SWAP1 PUSH2 0x8D JUMP JUMPDEST JUMPDEST POP SWAP1 POP PUSH2 0xBB SWAP2 SWAP1 PUSH2 0xBF JUMP JUMPDEST POP SWAP1 JUMP JUMPDEST PUSH2 0xE1 SWAP2 SWAP1 JUMPDEST DUP1 DUP3 GT ISZERO PUSH2 0xDD JUMPI PUSH1 0x0 DUP2 PUSH1 0x0 SWAP1 SSTORE POP PUSH1 0x1 ADD PUSH2 0xC5 JUMP JUMPDEST POP SWAP1 JUMP JUMPDEST SWAP1 JUMP JUMPDEST PUSH2 0x294 DUP1 PUSH2 0xF3 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN INVALID PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x4 CALLDATASIZE LT PUSH2 0x4C JUMPI PUSH1 0x0 CALLDATALOAD PUSH1 0xE0 SHR DUP1 PUSH4 0x43D726D6 EQ PUSH2 0x51 JUMPI DUP1 PUSH4 0x60CD2685 EQ PUSH2 0x5B JUMPI DUP1 PUSH4 0xC16431B9 EQ PUSH2 0x9D JUMPI DUP1 PUSH4 0xF0BA8440 EQ PUSH2 0xD5 JUMPI JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH2 0x59 PUSH2 0x117 JUMP JUMPDEST STOP JUMPDEST PUSH2 0x87 PUSH1 0x4 DUP1 CALLDATASIZE SUB PUSH1 0x20 DUP2 LT ISZERO PUSH2 0x71 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST DUP2 ADD SWAP1 DUP1 DUP1 CALLDATALOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 POP POP POP PUSH2 0x1F6 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 DUP3 DUP2 MSTORE PUSH1 0x20 ADD SWAP2 POP POP PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH2 0xD3 PUSH1 0x4 DUP1 CALLDATASIZE SUB PUSH1 0x40 DUP2 LT ISZERO PUSH2 0xB3 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST DUP2 ADD SWAP1 DUP1 DUP1 CALLDATALOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 DUP1 CALLDATALOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 POP POP POP PUSH2 0x20E JUMP JUMPDEST STOP JUMPDEST PUSH2 0x101 PUSH1 0x4 DUP1 CALLDATASIZE SUB PUSH1 0x20 DUP2 LT ISZERO PUSH2 0xEB JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST DUP2 ADD SWAP1 DUP1 DUP1 CALLDATALOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 POP POP POP PUSH2 0x225 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 DUP3 DUP2 MSTORE PUSH1 0x20 ADD SWAP2 POP POP PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH1 0x0 DUP1 SWAP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND EQ PUSH2 0x1BC JUMPI PUSH1 0x40 MLOAD PUSH32 0x8C379A000000000000000000000000000000000000000000000000000000000 DUP2 MSTORE PUSH1 0x4 ADD DUP1 DUP1 PUSH1 0x20 ADD DUP3 DUP2 SUB DUP3 MSTORE PUSH1 0x22 DUP2 MSTORE PUSH1 0x20 ADD DUP1 PUSH2 0x23E PUSH1 0x22 SWAP2 CODECOPY PUSH1 0x40 ADD SWAP2 POP POP PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 REVERT JUMPDEST PUSH1 0x0 DUP1 SWAP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND SELFDESTRUCT JUMPDEST PUSH1 0x0 PUSH1 0x1 DUP3 PUSH1 0x64 DUP2 LT PUSH2 0x205 JUMPI INVALID JUMPDEST ADD SLOAD SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST DUP1 PUSH1 0x1 DUP4 PUSH1 0x64 DUP2 LT PUSH2 0x21C JUMPI INVALID JUMPDEST ADD DUP2 SWAP1 SSTORE POP POP POP JUMP JUMPDEST PUSH1 0x1 DUP2 PUSH1 0x64 DUP2 LT PUSH2 0x232 JUMPI INVALID JUMPDEST ADD PUSH1 0x0 SWAP2 POP SWAP1 POP SLOAD DUP2 JUMP INVALID 0x4F PUSH15 0x6C79206F776E65722063616E206361 PUSH13 0x6C20746869732066756E637469 PUSH16 0x6E2EA265627A7A72315820965C55D5AA 0xCD SSTORE PUSH16 0xDC2807CEF18B41DA28C73BA7A04927A2 0x23 0x4F PUSH2 0x7033 0x28 0x5C 0x5E PUSH5 0x736F6C6343 STOP SDIV GT STOP ORIGIN ",
	"sourceMap": "26:553:0:-;;;221:65;8:9:-1;5:2;;;30:1;27;20:12;5:2;221:65:0;258:10;250:5;;:18;;;;;;;;;;;;;;;;;;272:10;;;;;;;;280:1;272:10;;;;;:4;:10;;;;;;;:::i;:::-;;26:553;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::i;:::-;;;:::o;:::-;;;;;;;;;;;;;;;;;;;;;;;;;;;:::o;:::-;;;;;;;"
}
*/

/* test function signatures
put function sig: c16431b9
close function sig: 43d726d6
data function sig: 60cd2685
*/

// MakeChain creates a chain of n blocks starting at and including parent.
// the returned hash chain is ordered head->parent.
func MakeChain(n int, parent *types.Block, chainGen func(int, *core.BlockGen)) ([]*types.Block, *core.BlockChain) {
	config := params.TestChainConfig
	blocks, _ := core.GenerateChain(config, parent, ethash.NewFaker(), Testdb, n, chainGen)
	chain, _ := core.NewBlockChain(Testdb, nil, params.TestChainConfig, ethash.NewFaker(), vm.Config{}, nil)
	return blocks, chain
}

func TestSelfDestructChainGen(i int, block *core.BlockGen) {
	signer := types.HomesteadSigner{}
	switch i {
	case 0:
		// Block 1 is mined by Account1Addr
		// Account1Addr creates a new contract
		block.SetCoinbase(TestBankAddress)
		tx, _ := types.SignTx(types.NewContractCreation(0, big.NewInt(0), 1000000, big.NewInt(0), ContractCode), signer, TestBankKey)
		ContractAddr = crypto.CreateAddress(TestBankAddress, 0)
		block.AddTx(tx)
	case 1:
		// Block 2 is mined by Account1Addr
		// Account1Addr self-destructs the contract
		block.SetCoinbase(TestBankAddress)
		data := common.Hex2Bytes("43D726D6")
		tx, _ := types.SignTx(types.NewTransaction(1, ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	}
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
		tx3, _ := types.SignTx(types.NewContractCreation(nonce, big.NewInt(0), 1000000, big.NewInt(0), ContractCode), signer, Account1Key)
		ContractAddr = crypto.CreateAddress(Account1Addr, nonce)
		block.AddTx(tx1)
		block.AddTx(tx2)
		block.AddTx(tx3)
	case 2:
		// Block 3 has a single tx from the bankAccount to the contract, that transfers no value
		// Block 3 is mined by Account2Addr
		block.SetCoinbase(Account2Addr)
		data := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003")
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	case 3:
		// Block 4 has three txs from bankAccount to the contract, that transfer no value
		// Two set the two original slot positions to 0 and one sets another position to a new value
		// Block 4 is mined by Account2Addr
		block.SetCoinbase(Account2Addr)
		data1 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		data2 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000")
		data3 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000009")

		nonce := block.TxNonce(TestBankAddress)
		tx1, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data1), signer, TestBankKey)
		nonce++
		tx2, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data2), signer, TestBankKey)
		nonce++
		tx3, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data3), signer, TestBankKey)
		block.AddTx(tx1)
		block.AddTx(tx2)
		block.AddTx(tx3)
	case 4:
		// Block 5 has one tx from bankAccount to the contract, that transfers no value
		// It sets the remaining storage value to zero
		// Block 5 is mined by Account1Addr
		block.SetCoinbase(Account1Addr)
		data := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000")
		nonce := block.TxNonce(TestBankAddress)
		tx, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	case 5:
		// Block 6 has a tx from Account1Key which self-destructs the contract, it transfers no value
		// Block 6 is mined by Account2Addr
		block.SetCoinbase(Account2Addr)
		data := common.Hex2Bytes("43D726D6")
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(Account1Addr), ContractAddr, big.NewInt(0), 100000, nil, data), signer, Account1Key)
		block.AddTx(tx)
	}
}

// AddressToLeafKey hashes an returns an address
func AddressToLeafKey(address common.Address) []byte {
	return crypto.Keccak256(address[:])
}

// AddressToEncodedPath hashes an address and appends the even-number leaf flag to it
func AddressToEncodedPath(address common.Address) []byte {
	addrHash := crypto.Keccak256(address[:])
	decodedPath := append(EvenLeafFlag, addrHash...)
	return decodedPath
}
