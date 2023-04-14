package integration_test

import (
	"context"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
	integration "github.com/cerc-io/ipld-eth-server/v5/test"
)

var (
	nonExistingBlockHash = common.HexToHash("0x111111111111111111111111111111111111111111111111111111111111111")
	nonExistingAddress   = common.HexToAddress("0x1111111111111111111111111111111111111111")
	randomAddr           = common.HexToAddress("0x1C3ab14BBaD3D99F4203bd7a11aCB94882050E6f")
	randomHash           = crypto.Keccak256Hash(randomAddr.Bytes())

	erc20TotalSupply, _ = new(big.Int).SetString("1000000000000000000000", 10)
	ercTotalSupplyIndex = common.HexToHash("0x2")

	delayInterval = time.Second * 1
)

var _ = Describe("Basic integration test", func() {
	ctx := context.Background()

	var contract *integration.ContractDeployed
	var tx *integration.Tx
	var contractErr error
	var txErr error

	Describe("get Block", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())

			time.Sleep(delayInterval)
		})

		It("get not existing block by number", func() {
			blockNum := big.NewInt(contract.BlockNumber + 100)

			gethBlock, err := gethClient.BlockByNumber(ctx, blockNum)
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, blockNum)
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		It("get not existing block by hash", func() {
			gethBlock, err := gethClient.BlockByHash(ctx, nonExistingBlockHash)
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByHash(ctx, nonExistingBlockHash)
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		It("get block by number", func() {
			blockNum := big.NewInt(contract.BlockNumber)

			gethBlock, err := gethClient.BlockByNumber(ctx, blockNum)
			Expect(err).ToNot(HaveOccurred())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, blockNum)
			Expect(err).ToNot(HaveOccurred())

			// check headers are equals
			Expect(gethBlock.Header()).To(Equal(ipldBlock.Header()))

			gethTxs := gethBlock.Transactions()
			ipldTxs := ipldBlock.Transactions()

			Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
			Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		})

		It("get block by hash", func() {
			gethBlock, err := gethClient.BlockByHash(ctx, contract.BlockHash)
			Expect(err).ToNot(HaveOccurred())

			ipldBlock, err := ipldClient.BlockByHash(ctx, contract.BlockHash)
			Expect(err).ToNot(HaveOccurred())

			// check headers are equals
			compareBlocks(gethBlock, ipldBlock)

			gethTxs := gethBlock.Transactions()
			ipldTxs := ipldBlock.Transactions()

			Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
			Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		})
	})

	Describe("Transaction", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("Get tx by hash", func() {
			gethTx, _, err := gethClient.TransactionByHash(ctx, contract.TransactionHash)
			Expect(err).ToNot(HaveOccurred())

			ipldTx, _, err := ipldClient.TransactionByHash(ctx, contract.TransactionHash)
			Expect(err).ToNot(HaveOccurred())

			compareTxs(gethTx, ipldTx)

			Expect(gethTx.Hash()).To(Equal(ipldTx.Hash()))
		})

		It("Get tx by block hash and index", func() {
			gethTx, err := gethClient.TransactionInBlock(ctx, contract.BlockHash, 0)
			Expect(err).ToNot(HaveOccurred())

			ipldTx, err := ipldClient.TransactionInBlock(ctx, contract.BlockHash, 0)
			Expect(err).ToNot(HaveOccurred())

			compareTxs(gethTx, ipldTx)
		})
	})

	Describe("Receipt", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("Get tx receipt", func() {
			gethReceipt, err := gethClient.TransactionReceipt(ctx, contract.TransactionHash)
			Expect(err).ToNot(HaveOccurred())

			ipldReceipt, err := ipldClient.TransactionReceipt(ctx, contract.TransactionHash)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethReceipt).To(Equal(ipldReceipt))

			rlpGeth, err := rlp.EncodeToBytes(gethReceipt)
			Expect(err).ToNot(HaveOccurred())

			rlpIpld, err := rlp.EncodeToBytes(ipldReceipt)
			Expect(err).ToNot(HaveOccurred())

			Expect(rlpGeth).To(Equal(rlpIpld))
		})
	})

	Describe("FilterLogs", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("with blockhash", func() {
			blockHash := contract.BlockHash
			filterQuery := ethereum.FilterQuery{
				//Addresses: addresses,
				BlockHash: &blockHash,
				Topics:    [][]common.Hash{},
			}

			gethLogs, err := gethClient.FilterLogs(ctx, filterQuery)
			Expect(err).ToNot(HaveOccurred())

			ipldLogs, err := ipldClient.FilterLogs(ctx, filterQuery)
			Expect(err).ToNot(HaveOccurred())

			// not empty list
			Expect(gethLogs).ToNot(BeEmpty())

			Expect(len(gethLogs)).To(Equal(len(ipldLogs)))
			Expect(gethLogs).To(Equal(ipldLogs))
		})
	})

	Describe("CodeAt", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("gets code at non-existing address without block number", func() {
			gethCode, err := gethClient.CodeAt(ctx, nonExistingAddress, nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, nonExistingAddress, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of deployed contract without block number", func() {
			gethCode, err := gethClient.CodeAt(ctx, contract.Address, nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, contract.Address, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of deployed contract with block number", func() {
			gethCode, err := gethClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of contract that doesn't exist at this height", func() {
			gethCode, err := gethClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
		})
	})

	Describe("Get balance", func() {
		var newAddress common.Address
		rand.Read(newAddress[:])

		BeforeEach(func() {
			tx, txErr = integration.SendEth(newAddress, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
		})

		It("gets balance for an account with eth with block number", func() {
			gethBalance, err := gethClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets balance for an account with eth without block number", func() {
			gethBalance, err := gethClient.BalanceAt(ctx, newAddress, nil)
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, newAddress, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})

		It("gets historical balance for an account with eth with block number", func() {
			gethBalance, err := gethClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets balance for a non-existing account without block number", func() {
			gethBalance, err := gethClient.BalanceAt(ctx, nonExistingAddress, nil)
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, nonExistingAddress, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets balance for an non-existing block number", func() {
			gethBalance, err := gethClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber+3))
			Expect(err).To(MatchError("header not found"))

			ipldBalance, err := ipldClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber+3))
			Expect(err).To(MatchError("header not found"))

			Expect(gethBalance).To(Equal(ipldBalance))
		})
	})

	Describe("Get Storage", func() {
		var contractSalt string
		countAIndex := common.HexToHash("0x5")

		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
			Expect(contract.BlockNumber).ToNot(BeZero())

			contractSalt = common.Bytes2Hex(contract.BlockHash[:10])
		})

		It("gets ERC20 total supply (with block number)", func() {
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethStorage)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldStorage, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets ERC20 total supply (without block number)", func() {
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, nil)
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethStorage)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldStorage, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets storage for non-existing account", func() {
			gethStorage, err := gethClient.StorageAt(ctx, nonExistingAddress, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, nonExistingAddress, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets storage for non-existing contract slot", func() {
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, randomHash, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, contract.Address, randomHash, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets storage for non-existing contract", func() {
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(0))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets storage for non-existing block number", func() {
			blockNum := contract.BlockNumber + 100
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(blockNum))
			Expect(err).To(MatchError("header not found"))

			ipldStorage, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(blockNum))
			Expect(err).To(MatchError("header not found"))
			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets storage for SLV countA after tx", func() {
			slvContract, contractErr := integration.Create2Contract("SLVToken", contractSalt)
			Expect(contractErr).ToNot(HaveOccurred())

			gethStorage, err := gethClient.StorageAt(ctx, slvContract.Address, countAIndex, big.NewInt(slvContract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			slvCountA := new(big.Int).SetBytes(gethStorage)

			err = waitForBlock(ctx, ipldClient, slvContract.BlockNumber)
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, slvContract.Address, countAIndex, big.NewInt(slvContract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldCountA := new(big.Int).SetBytes(ipldStorage)
			Expect(ipldCountA).To(Equal(slvCountA))

			inc, err := integration.IncrementCount("A", slvContract.Address)
			Expect(err).ToNot(HaveOccurred())
			slvCountA.Add(slvCountA, big.NewInt(1))

			ipldStorage, err = ipldClient.StorageAt(ctx, slvContract.Address, countAIndex, inc.BlockNumber)
			Expect(err).ToNot(HaveOccurred())

			ipldCountA = new(big.Int).SetBytes(ipldStorage)
			Expect(ipldCountA).To(Equal(slvCountA))
		})

		It("gets storage after destruction and redeploy", func() {
			slvContract, contractErr := integration.Create2Contract("SLVToken", contractSalt)
			Expect(contractErr).ToNot(HaveOccurred())

			tx, err := integration.DestroyContract(contract.Address)
			Expect(err).ToNot(HaveOccurred())

			slvTx, err := integration.DestroyContract(slvContract.Address)
			Expect(err).ToNot(HaveOccurred())

			gethStorage1, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())
			gethStorage2, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethStorage1).NotTo(Equal(gethStorage2))
			Expect(gethStorage2).To(Equal(eth.EmptyNodeValue))

			ipldStorage1, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())
			ipldStorage2, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			Expect(ipldStorage1).To(Equal(gethStorage1))
			Expect(ipldStorage2).To(Equal(gethStorage2))

			// Query the current block
			ipldStorage3, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(ipldStorage2).To(Equal(ipldStorage3))

			// Check for SLV contract
			gethStorage, err := gethClient.StorageAt(ctx, slvContract.Address, countAIndex, big.NewInt(slvTx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(eth.EmptyNodeValue))

			ipldStorage, err := ipldClient.StorageAt(ctx, slvContract.Address, countAIndex, big.NewInt(slvTx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(ipldStorage).To(Equal(gethStorage))

			// Redeploy to same address
			slvContract, contractErr = integration.Create2Contract("SLVToken", contractSalt)
			Expect(contractErr).ToNot(HaveOccurred())

			gethStorage, err = gethClient.StorageAt(ctx, slvContract.Address, countAIndex, big.NewInt(slvContract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err = ipldClient.StorageAt(ctx, slvContract.Address, countAIndex, big.NewInt(slvContract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethStorage).To(Equal(ipldStorage))
			ipldCountA := new(big.Int).SetBytes(ipldStorage)
			Expect(ipldCountA.String()).To(Equal("0"))

		})
	})

	Describe("eth call", func() {
		var msg ethereum.CallMsg

		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())

			msg = ethereum.CallMsg{
				To:   &contract.Address,
				Data: common.Hex2Bytes("18160ddd"), // totalSupply()
			}
		})

		It("calls totalSupply() without block number", func() {
			gethResult, err := gethClient.CallContract(ctx, msg, nil)
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethResult)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldResult, err := ipldClient.CallContract(ctx, msg, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethResult).To(Equal(ipldResult))
		})

		It("calls totalSupply() with block number", func() {
			gethResult, err := gethClient.CallContract(ctx, msg, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethResult)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldResult, err := ipldClient.CallContract(ctx, msg, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethResult).To(Equal(ipldResult))
		})

		It("calls totalSupply() with block hash", func() {
			gethResult, err := gethClient.CallContractAtHash(ctx, msg, contract.BlockHash)
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethResult)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldResult, err := ipldClient.CallContractAtHash(ctx, msg, contract.BlockHash)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethResult).To(Equal(ipldResult))
		})
	})

	Describe("Chain ID", func() {
		It("Check chain id", func() {
			gethChainId, err := gethClient.ChainID(ctx)
			Expect(err).ToNot(HaveOccurred())

			ipldChainId, err := ipldClient.ChainID(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethChainId).To(Equal(ipldChainId))
		})
	})
})

func compareBlocks(block1 *types.Block, block2 *types.Block) {
	GinkgoHelper()
	Expect(block1.Header()).To(Equal(block2.Header()))
	Expect(block1.Uncles()).To(Equal(block2.Uncles()))

	txs1 := block1.Transactions()
	txs2 := block2.Transactions()

	Expect(len(txs1)).To(Equal(len(txs2)))
	for i, tx := range txs1 {
		compareTxs(tx, txs2[i])
	}
}

func compareTxs(tx1 *types.Transaction, tx2 *types.Transaction) {
	GinkgoHelper()
	Expect(tx1.Data()).To(Equal(tx2.Data()))
	Expect(tx1.Hash()).To(Equal(tx2.Hash()))
	Expect(tx1.Size()).To(Equal(tx2.Size()))

	signer := types.NewLondonSigner(big.NewInt(testChainId))

	gethSender, err := types.Sender(signer, tx1)
	Expect(err).ToNot(HaveOccurred())

	ipldSender, err := types.Sender(signer, tx2)
	Expect(err).ToNot(HaveOccurred())

	Expect(gethSender).To(Equal(ipldSender))
}
