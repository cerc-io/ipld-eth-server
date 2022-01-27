package integration_test

import (
	"context"
	"math/big"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	integration "github.com/vulcanize/ipld-eth-server/test"
)

var _ = Describe("WatchAddressIntegration", func() {
	dbWrite, err := strconv.ParseBool(os.Getenv("DB_WRITE"))
	Expect(err).To(BeNil())

	gethHttpPath := "http://127.0.0.1:8545"
	gethRPCClient, err := rpc.Dial(gethHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ipldEthHttpPath := "http://127.0.0.1:8081"
	ipldClient, err := ethclient.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())
	ipldRPCClient, err := rpc.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ctx := context.Background()

	var (
		txErr       error
		contractErr error

		gethMethod = "statediff_watchAddress"
		ipldMethod = "vdb_watchAddress"

		contract1 *integration.ContractDeployed
		contract2 *integration.ContractDeployed
		contract3 *integration.ContractDeployed

		prevBalance1 *big.Int
		prevBalance2 *big.Int
		prevBalance3 *big.Int

		actualBalance1 *big.Int
		actualBalance2 *big.Int
		actualBalance3 *big.Int
	)

	BeforeEach(func() {
		if !dbWrite {
			Skip("skipping WatchAddress integration tests")
		}
	})

	It("WatchAddress test init", func() {
		// Deploy three contracts
		contract1, contractErr = integration.DeployContract()
		Expect(contractErr).ToNot(HaveOccurred())

		contract2, contractErr = integration.DeployContract()
		Expect(contractErr).ToNot(HaveOccurred())

		contract3, contractErr = integration.DeployContract()
		Expect(contractErr).ToNot(HaveOccurred())

		// Get initial balances for all the contracts
		actualBalance1 = big.NewInt(0)
		prevBalance1 = big.NewInt(0)
		initBalance1, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(initBalance1.String()).To(Equal(actualBalance1.String()))

		actualBalance2 = big.NewInt(0)
		prevBalance2 = big.NewInt(0)
		initBalance2, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(initBalance2.String()).To(Equal(actualBalance2.String()))

		actualBalance3 = big.NewInt(0)
		prevBalance3 = big.NewInt(0)
		initBalance3, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(initBalance3.String()).To(Equal(actualBalance3.String()))
	})

	Context("no contracts being watched", func() {
		It("indexes state for all the contracts", func() {
			// Send eth to all three contract accounts
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			_, txErr = integration.SendEth(contract2.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			_, txErr = integration.SendEth(contract3.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(actualBalance3.String()))
			prevBalance3.Set(actualBalance3)
		})
	})

	Context("one contract being watched", func() {
		It("indexes state only for the watched contract", func() {
			operation := "AddAddresses"
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract1.Address,
					CreatedAt: uint64(contract1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Send eth to all three contract accounts
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			_, txErr = integration.SendEth(contract2.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(prevBalance2.String()))

			_, txErr = integration.SendEth(contract3.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(prevBalance3.String()))
		})
	})

	Context("contract added to a non-empty watch-list", func() {
		It("indexes state only for the watched contracts", func() {
			operation := "AddAddresses"
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract2.Address,
					CreatedAt: uint64(contract2.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Send eth to all three contract accounts
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			_, txErr = integration.SendEth(contract2.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			_, txErr = integration.SendEth(contract3.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(prevBalance3.String()))
		})
	})

	Context("contract removed from the watch-list", func() {
		It("indexes state only for the watched contract", func() {
			operation := "RemoveAddresses"
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract1.Address,
					CreatedAt: uint64(contract1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Send eth to all three contract accounts
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(prevBalance1.String()))

			_, txErr = integration.SendEth(contract2.Address, "0.01")
			// time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			_, txErr = integration.SendEth(contract3.Address, "0.01")
			// time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(prevBalance3.String()))
		})
	})

	Context("set the list of watched addresses", func() {
		It("indexes state only for the watched contracts", func() {
			operation := "SetAddresses"
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract1.Address,
					CreatedAt: uint64(contract1.BlockNumber),
				},
				{
					Address:   contract3.Address,
					CreatedAt: uint64(contract3.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Send eth to all three contract accounts
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			_, txErr = integration.SendEth(contract2.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(prevBalance2.String()))

			_, txErr = integration.SendEth(contract3.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(actualBalance3.String()))
			prevBalance3.Set(actualBalance3)
		})
	})

	Context("clear the list of watched addresses", func() {
		It("indexes state for all the contracts", func() {
			operation := "ClearAddresses"
			args := []sdtypes.WatchAddressArg{}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Send eth to all three contract accounts
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			_, txErr = integration.SendEth(contract2.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			_, txErr = integration.SendEth(contract3.Address, "0.01")
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(actualBalance3.String()))
			prevBalance3.Set(actualBalance3)
		})
	})

	Context("with invalid args", func() {
		It("returns an error on invalid operation arg", func() {
			operation := "WrongOp"
			args := []sdtypes.WatchAddressArg{}

			gethErr := gethRPCClient.Call(nil, gethMethod, operation, args)
			Expect(gethErr).To(HaveOccurred())

			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).To(HaveOccurred())

			Expect(ipldErr).To(Equal(gethErr))
		})

		It("returns an error on args of invalid type", func() {
			operation := "AddAddresses"
			args := []string{"WrongArg"}

			gethErr := gethRPCClient.Call(nil, gethMethod, operation, args)
			Expect(gethErr).To(HaveOccurred())

			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).To(HaveOccurred())

			Expect(ipldErr).To(Equal(gethErr))
		})
	})
})
