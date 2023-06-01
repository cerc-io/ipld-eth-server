package integration_test

import (
	"context"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cerc-io/ipld-eth-server/v5/integration"
	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
)

var _ = Describe("Direct proxy integration test", Label("proxy"), func() {
	ctx := context.Background()

	var contract *integration.ContractDeployed
	var tx *integration.Tx
	var contractErr error
	var txErr error

	Describe("get Block", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("get not existing block by number", func() {
			blockNum := contract.BlockNumber + 100

			gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(blockNum))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(blockNum))
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
			blockNum := contract.BlockNumber

			_, err := gethClient.BlockByNumber(ctx, big.NewInt(blockNum))
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.BlockByNumber(ctx, big.NewInt(blockNum))
			Expect(err).To(HaveOccurred())
		})

		It("get block by hash", func() {
			_, err := gethClient.BlockByHash(ctx, contract.BlockHash)
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.BlockByHash(ctx, contract.BlockHash)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Transaction", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("Get tx by hash", func() {
			_, _, err := gethClient.TransactionByHash(ctx, contract.TransactionHash)
			Expect(err).ToNot(HaveOccurred())

			_, _, err = ipldClient.TransactionByHash(ctx, contract.TransactionHash)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("Get tx by block hash and index", func() {
			_, err := gethClient.TransactionInBlock(ctx, contract.BlockHash, 0)
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.TransactionInBlock(ctx, contract.BlockHash, 0)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})
	})

	Describe("Receipt", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("Get tx receipt", func() {
			_, err := gethClient.TransactionReceipt(ctx, contract.TransactionHash)
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.TransactionReceipt(ctx, contract.TransactionHash)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
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
			// empty list
			Expect(ipldLogs).To(BeEmpty())
		})
	})

	Describe("CodeAt", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("gets code of deployed contract with block number", func() {
			_, err := gethClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())
			Expect(ipldCode).To(BeEmpty())
		})
		It("gets code of contract that doesn't exist at this height", func() {
			gethCode, err := gethClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, contract.Address, big.NewInt(contract.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
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
			_, err := gethClient.CodeAt(ctx, contract.Address, nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, contract.Address, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(ipldCode).To(BeEmpty())
		})
	})

	Describe("Get balance", func() {
		var newAddress common.Address
		rand.Read(newAddress[:])

		BeforeEach(func() {
			tx, txErr = integration.SendEth(newAddress, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
		})

		It("gets balance for an account with eth without block number", func() {
			gethBalance, err := gethClient.BalanceAt(ctx, newAddress, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(gethBalance.String()).To(Equal("10000000000000000"))

			ipldBalance, err := ipldClient.BalanceAt(ctx, newAddress, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(ipldBalance.String()).To(Equal("0"))
		})
		It("gets balance for an account with eth with block number", func() {
			_, err := gethClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber))
			Expect(err).To(MatchError("header not found"))
		})
		It("gets historical balance for an account with eth with block number", func() {
			_, err := gethClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.BalanceAt(ctx, newAddress, big.NewInt(tx.BlockNumber-1))
			Expect(err).To(MatchError("header not found"))
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

			ipldBalance, err := ipldClient.BalanceAt(ctx, nonExistingAddress, big.NewInt(tx.BlockNumber+3))
			Expect(err).To(MatchError("header not found"))

			Expect(gethBalance).To(Equal(ipldBalance))
		})
	})

	Describe("Get Storage", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			Expect(contractErr).ToNot(HaveOccurred())
		})

		It("gets ERC20 total supply (without block number)", func() {
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, nil)
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethStorage)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldStorage, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(ipldStorage).To(Equal(make([]byte, 32)))
		})

		It("gets ERC20 total supply (with block number)", func() {
			gethStorage, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethStorage)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			_, err = ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).To(MatchError("header not found"))
		})

		It("gets storage for non-existing account", func() {
			_, err := gethClient.StorageAt(ctx, nonExistingAddress, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.StorageAt(ctx, nonExistingAddress, ercTotalSupplyIndex, big.NewInt(contract.BlockNumber))
			Expect(err).To(MatchError("header not found"))
		})

		It("gets storage for non-existing contract slot", func() {
			_, err := gethClient.StorageAt(ctx, contract.Address, randomHash, big.NewInt(contract.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.StorageAt(ctx, contract.Address, randomHash, big.NewInt(contract.BlockNumber))
			Expect(err).To(MatchError("header not found"))
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

		It("get storage after self destruct", func() {
			tx, err := integration.DestroyContract(contract.Address)
			Expect(err).ToNot(HaveOccurred())

			gethStorage1, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber-1))
			Expect(err).ToNot(HaveOccurred())
			gethStorage2, err := gethClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethStorage1).NotTo(Equal(gethStorage2))
			Expect(gethStorage2).To(Equal(eth.EmptyNodeValue))

			_, err = ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber-1))
			Expect(err).To(MatchError("header not found"))

			_, err = ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, big.NewInt(tx.BlockNumber))
			Expect(err).To(MatchError("header not found"))

			// Query the current block
			ipldStorage3, err := ipldClient.StorageAt(ctx, contract.Address, ercTotalSupplyIndex, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(eth.EmptyNodeValue).To(Equal(ipldStorage3))
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
	})

	Describe("Chain ID", func() {
		It("Check chain id", func() {
			_, err := gethClient.ChainID(ctx)
			Expect(err).ToNot(HaveOccurred())

			_, err = ipldClient.ChainID(ctx)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
