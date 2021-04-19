package integration_test

import (
	"context"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	//"github.com/ethereum/go-ethereum"
	//"github.com/ethereum/go-ethereum/common"
	//"github.com/ethereum/go-ethereum/rlp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	integration "github.com/vulcanize/ipld-eth-server/test"
	"math/big"

	"github.com/ethereum/go-ethereum/ethclient"
)

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
			nonExistingBlockHash := "0x111111111111111111111111111111111111111111111111111111111111111"

			gethBlock, err := gethClient.BlockByHash(ctx, common.HexToHash(nonExistingBlockHash))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByHash(ctx, common.HexToHash(nonExistingBlockHash))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		//It("get block by number", func() {
		//	Expect(contractErr).ToNot(HaveOccurred())
		//
		//	blockNum := contract.BlockNumber
		//
		//	gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
		//	Expect(err).ToNot(HaveOccurred())
		//
		//	ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
		//	Expect(err).ToNot(HaveOccurred())
		//
		//	// check headers are equals
		//	Expect(gethBlock.Header()).To(Equal(ipldBlock.Header()))
		//
		//	gethTxs := gethBlock.Transactions()
		//	ipldTxs := ipldBlock.Transactions()
		//
		//	Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
		//	Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		//})
		//
		//It("get block by hash", func() {
		//
		//	gethBlock, err := gethClient.BlockByHash(ctx, common.HexToHash(contract.BlockHash))
		//	fmt.Printf("contract info: %+v", contract)
		//	Expect(err).ToNot(HaveOccurred())
		//
		//	ipldBlock, err := ipldClient.BlockByHash(ctx, common.HexToHash(contract.BlockHash))
		//	Expect(err).ToNot(HaveOccurred())
		//
		//	// check headers are equals
		//	Expect(gethBlock).To(Equal(ipldBlock))
		//	Expect(gethBlock.Header()).To(Equal(ipldBlock.Header()))
		//
		//	gethTxs := gethBlock.Transactions()
		//	ipldTxs := ipldBlock.Transactions()
		//
		//	Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
		//	Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		//})
	})

	//Describe("Transaction", func() {
	//	txHash := "0xdb3d5ef2d4e3260e1b8c1bcbb09b2d8fe7a6423196a20b8a3fa6c09dd9d79073"
	//	blockHash := "0xb821ca79bd37174368073e469db92ead75148a95f7c24c49f2435fb7c7797588"
	//
	//	It("Get tx by hash", func() {
	//		gethTx, _, err := gethClient.TransactionByHash(ctx, common.HexToHash(txHash))
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		ipldTx, _, err := ipldClient.TransactionByHash(ctx, common.HexToHash(txHash))
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		Expect(gethTx).To(Equal(ipldTx))
	//
	//		Expect(gethTx.Hash()).To(Equal(ipldTx.Hash()))
	//	})
	//
	//	It("Get tx by block hash and index", func() {
	//		gethTx, err := gethClient.TransactionInBlock(ctx, common.HexToHash(blockHash), 0)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		ipldTx, err := ipldClient.TransactionInBlock(ctx, common.HexToHash(blockHash), 0)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		Expect(gethTx).To(Equal(ipldTx))
	//
	//		Expect(gethTx.Hash()).To(Equal(ipldTx.Hash()))
	//	})
	//
	//})
	//
	//Describe("Receipt", func() {
	//	txHash := "0xdb3d5ef2d4e3260e1b8c1bcbb09b2d8fe7a6423196a20b8a3fa6c09dd9d79073"
	//
	//	It("Get tx receipt", func() {
	//		gethReceipt, err := gethClient.TransactionReceipt(ctx, common.HexToHash(txHash))
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		ipldReceipt, err := ipldClient.TransactionReceipt(ctx, common.HexToHash(txHash))
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		Expect(gethReceipt).To(Equal(ipldReceipt))
	//
	//		rlpGeth, err := rlp.EncodeToBytes(gethReceipt)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		rlpIpld, err := rlp.EncodeToBytes(ipldReceipt)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		Expect(rlpGeth).To(Equal(rlpIpld))
	//	})
	//})
	//
	//Describe("FilterLogs", func() {
	//	//txHash := "0xdb3d5ef2d4e3260e1b8c1bcbb09b2d8fe7a6423196a20b8a3fa6c09dd9d79073"
	//	//blockHash := "0xb821ca79bd37174368073e469db92ead75148a95f7c24c49f2435fb7c7797588"
	//	blockHash := common.HexToHash(
	//		"0xb821ca79bd37174368073e469db92ead75148a95f7c24c49f2435fb7c7797588",
	//	)
	//
	//	It("with blockhash", func() {
	//		filterQuery := ethereum.FilterQuery{
	//			//Addresses: addresses,
	//			BlockHash: &blockHash,
	//			Topics:    [][]common.Hash{},
	//		}
	//
	//		gethLogs, err := gethClient.FilterLogs(ctx, filterQuery)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		ipldLogs, err := ipldClient.FilterLogs(ctx, filterQuery)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		// not empty list
	//		Expect(gethLogs).ToNot(BeEmpty())
	//
	//		Expect(len(gethLogs)).To(Equal(len(ipldLogs)))
	//		Expect(gethLogs).To(Equal(ipldLogs))
	//	})
	//})
	//
	//Describe("CodeAt", func() {
	//	contractAddress := "0xdEE08501Ef5b68339ca920227d6520A10B72b65b"
	//	It("Get code of deployed contract without block number", func() {
	//		gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(contractAddress), nil)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(contractAddress), nil)
	//		Expect(err).ToNot(HaveOccurred())
	//
	//		Expect(gethCode).To(Equal(ipldCode))
	//	})
	//})
})
