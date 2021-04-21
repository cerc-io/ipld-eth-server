package integration_test

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/rlp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	integration "github.com/vulcanize/ipld-eth-server/test"
	"math/big"

	"github.com/ethereum/go-ethereum/ethclient"
)

const nonExistingBlockHash = "0x111111111111111111111111111111111111111111111111111111111111111"
const nonExistingAddress = "0x1111111111111111111111111111111111111111"

var _ = Describe("Integration test", func() {
	gethHttpPath := "http://127.0.0.1:8545"
	gethClient, err := ethclient.Dial(gethHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ipldEthHttpPath := "http://127.0.0.1:8081"
	ipldClient, err := ethclient.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ctx := context.Background()

	var contract *integration.ContractDeployed
	var contractErr error

	Describe("get Block", func() {
		contract, contractErr = integration.DeployContract()

		It("get not existing block by number", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			blockNum := contract.BlockNumber + 100

			gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		It("get not existing block by hash", func() {
			gethBlock, err := gethClient.BlockByHash(ctx, common.HexToHash(nonExistingBlockHash))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByHash(ctx, common.HexToHash(nonExistingBlockHash))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		It("get block by number", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			blockNum := contract.BlockNumber

			gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).ToNot(HaveOccurred())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).ToNot(HaveOccurred())

			// check headers are equals
			Expect(gethBlock.Header()).To(Equal(ipldBlock.Header()))

			gethTxs := gethBlock.Transactions()
			ipldTxs := ipldBlock.Transactions()

			Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
			Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		})

		It("get block by hash", func() {

			gethBlock, err := gethClient.BlockByHash(ctx, common.HexToHash(contract.BlockHash))
			fmt.Printf("contract info: %+v", contract)
			Expect(err).ToNot(HaveOccurred())

			ipldBlock, err := ipldClient.BlockByHash(ctx, common.HexToHash(contract.BlockHash))
			Expect(err).ToNot(HaveOccurred())

			// check headers are equals
			Expect(gethBlock).To(Equal(ipldBlock))
			Expect(gethBlock.Header()).To(Equal(ipldBlock.Header()))

			gethTxs := gethBlock.Transactions()
			ipldTxs := ipldBlock.Transactions()

			Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
			Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		})
	})

	Describe("Transaction", func() {
		contract, contractErr = integration.DeployContract()

		It("Get tx by hash", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			gethTx, _, err := gethClient.TransactionByHash(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			ipldTx, _, err := ipldClient.TransactionByHash(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethTx).To(Equal(ipldTx))

			Expect(gethTx.Hash()).To(Equal(ipldTx.Hash()))
		})

		It("Get tx by block hash and index", func() {
			gethTx, err := gethClient.TransactionInBlock(ctx, common.HexToHash(contract.BlockHash), 0)
			Expect(err).ToNot(HaveOccurred())

			ipldTx, err := ipldClient.TransactionInBlock(ctx, common.HexToHash(contract.BlockHash), 0)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethTx).To(Equal(ipldTx))

			Expect(gethTx.Hash()).To(Equal(ipldTx.Hash()))
		})
	})

	Describe("Receipt", func() {
		contract, contractErr = integration.DeployContract()

		It("Get tx receipt", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			gethReceipt, err := gethClient.TransactionReceipt(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			ipldReceipt, err := ipldClient.TransactionReceipt(ctx, common.HexToHash(contract.TransactionHash))
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
		contract, contractErr = integration.DeployContract()

		It("with blockhash", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			blockHash := common.HexToHash(contract.BlockHash)
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
		contract, contractErr = integration.DeployContract()

		It("gets code at non-existing address without block number", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(nonExistingAddress), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(nonExistingAddress), nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of deployed contract without block number", func() {
			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(contract.Address), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(contract.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of contract that doesn't exist at this height", func() {
			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(contract.Address), big.NewInt(int64(contract.BlockNumber-1)))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(contract.Address), big.NewInt(int64(contract.BlockNumber-1)))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
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
