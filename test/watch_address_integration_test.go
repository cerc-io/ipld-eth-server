package integration_test

import (
	"context"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	integration "github.com/cerc-io/ipld-eth-server/v4/test"
)

var (
	gethMethod = "statediff_watchAddress"
	ipldMethod = "vdb_watchAddress"

	sleepInterval = 2 * time.Second
)

var _ = Describe("WatchAddress integration test", func() {
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

	var (
		ctx = context.Background()

		txErr       error
		contractErr error
		incErr      error

		contract1 *integration.ContractDeployed
		contract2 *integration.ContractDeployed
		contract3 *integration.ContractDeployed

		countAIndex string

		prevBalance1 *big.Int
		prevBalance2 *big.Int
		prevBalance3 *big.Int

		actualBalance1 *big.Int
		actualBalance2 *big.Int
		actualBalance3 *big.Int

		prevCountA1 *big.Int
		prevCountA2 *big.Int
		prevCountA3 *big.Int

		actualCountA1 *big.Int
		actualCountA2 *big.Int
		actualCountA3 *big.Int
	)

	BeforeEach(func() {
		if !dbWrite {
			Skip("skipping WatchAddress API integration tests")
		}
	})

	It("test init", func() {
		// Deploy three contracts
		contract1, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		contract2, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		contract3, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		// Get the storage slot key
		storageSlotAKey, err := integration.GetStorageSlotKey("SLVToken", "countA")
		Expect(err).ToNot(HaveOccurred())
		countAIndex = storageSlotAKey.Key

		// Clear out watched addresses
		err = integration.ClearWatchedAddresses(gethRPCClient)
		Expect(err).ToNot(HaveOccurred())

		// Get initial balances for all the contracts
		// Contract 1
		actualBalance1 = big.NewInt(0)
		initBalance1, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(initBalance1.String()).To(Equal(actualBalance1.String()))
		prevBalance1 = big.NewInt(0)

		// Contract 2
		actualBalance2 = big.NewInt(0)
		initBalance2, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(initBalance2.String()).To(Equal(actualBalance2.String()))
		prevBalance2 = big.NewInt(0)

		// Contract 3
		actualBalance3 = big.NewInt(0)
		initBalance3, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(initBalance3.String()).To(Equal(actualBalance3.String()))
		prevBalance3 = big.NewInt(0)

		// Get initial storage values for the contracts
		// Contract 1, countA
		actualCountA1 = big.NewInt(0)
		ipldCountA1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
		Expect(err).ToNot(HaveOccurred())
		ipldCountA1 := new(big.Int).SetBytes(ipldCountA1Storage)
		Expect(ipldCountA1.String()).To(Equal(actualCountA1.String()))
		prevCountA1 = big.NewInt(0)

		// Contract 2, countA
		actualCountA2 = big.NewInt(0)
		ipldCountA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
		Expect(err).ToNot(HaveOccurred())
		ipldCountA2 := new(big.Int).SetBytes(ipldCountA2Storage)
		Expect(ipldCountA2.String()).To(Equal(actualCountA2.String()))
		prevCountA2 = big.NewInt(0)

		// Contract 3, countA
		actualCountA3 = big.NewInt(0)
		ipldCountA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
		Expect(err).ToNot(HaveOccurred())
		ipldCountA3 := new(big.Int).SetBytes(ipldCountA3Storage)
		Expect(ipldCountA3.String()).To(Equal(actualCountA2.String()))
		prevCountA3 = big.NewInt(0)
	})

	defer It("test cleanup", func() {
		// Clear out watched addresses
		err := integration.ClearWatchedAddresses(gethRPCClient)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("no contracts being watched", func() {
		It("indexes state for all the contracts", func() {
			// WatchedAddresses = []
			// Send eth to all three contract accounts
			// Contract 1
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			// Contract 2
			_, txErr = integration.SendEth(contract2.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			// Contract 3
			_, txErr = integration.SendEth(contract3.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(actualBalance3.String()))
			prevBalance3.Set(actualBalance3)

			// Increment counts
			// Contract 1, countA
			_, incErr = integration.IncrementCount(contract1.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA1.Add(actualCountA1, big.NewInt(1))

			countA1AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1AfterIncrement := new(big.Int).SetBytes(countA1AfterIncrementStorage)
			Expect(countA1AfterIncrement.String()).To(Equal(actualCountA1.String()))
			prevCountA1.Set(actualCountA1)

			// Contract 2, countA
			_, incErr = integration.IncrementCount(contract2.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA2.Add(actualCountA2, big.NewInt(1))

			countA2AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2AfterIncrement := new(big.Int).SetBytes(countA2AfterIncrementStorage)
			Expect(countA2AfterIncrement.String()).To(Equal(actualCountA2.String()))
			prevCountA2.Set(actualCountA2)

			// Contract 3, countA
			_, incErr = integration.IncrementCount(contract3.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA3.Add(actualCountA3, big.NewInt(1))

			countA3AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3AfterIncrement := new(big.Int).SetBytes(countA3AfterIncrementStorage)
			Expect(countA3AfterIncrement.String()).To(Equal(actualCountA3.String()))
			prevCountA3.Set(actualCountA3)
		})
	})

	Context("one contract being watched", func() {
		It("indexes state only for the watched contract", func() {
			operation := sdtypes.Add
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract1.Address,
					CreatedAt: uint64(contract1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// WatchedAddresses = [Contract1]
			// Send eth to all three contract accounts
			// Contract 1
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			// Contract 2
			_, txErr = integration.SendEth(contract2.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(prevBalance2.String()))

			// Contract 3
			_, txErr = integration.SendEth(contract3.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(prevBalance3.String()))

			// Increment counts
			// Contract 1, countA
			_, incErr = integration.IncrementCount(contract1.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA1.Add(actualCountA1, big.NewInt(1))

			countA1AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1AfterIncrement := new(big.Int).SetBytes(countA1AfterIncrementStorage)
			Expect(countA1AfterIncrement.String()).To(Equal(actualCountA1.String()))
			prevCountA1.Set(actualCountA1)

			// Contract 2, countA
			_, incErr = integration.IncrementCount(contract2.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA2.Add(actualCountA2, big.NewInt(1))

			countA2AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2AfterIncrement := new(big.Int).SetBytes(countA2AfterIncrementStorage)
			Expect(countA2AfterIncrement.String()).To(Equal(prevCountA2.String()))

			// Contract 3, countA
			_, incErr = integration.IncrementCount(contract3.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA3.Add(actualCountA3, big.NewInt(1))

			countA3AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3AfterIncrement := new(big.Int).SetBytes(countA3AfterIncrementStorage)
			Expect(countA3AfterIncrement.String()).To(Equal(prevCountA3.String()))
		})
	})

	Context("contract added to a non-empty watch-list", func() {
		It("indexes state only for the watched contracts", func() {
			operation := sdtypes.Add
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract2.Address,
					CreatedAt: uint64(contract2.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// WatchedAddresses = [Contract1, Contract2]
			// Send eth to all three contract accounts
			// Contract 1
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			// Contract 2
			_, txErr = integration.SendEth(contract2.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			// Contract 3
			_, txErr = integration.SendEth(contract3.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(prevBalance3.String()))

			// Increment counts
			// Contract 1, countA
			_, incErr = integration.IncrementCount(contract1.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA1.Add(actualCountA1, big.NewInt(1))

			countA1AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1AfterIncrement := new(big.Int).SetBytes(countA1AfterIncrementStorage)
			Expect(countA1AfterIncrement.String()).To(Equal(actualCountA1.String()))
			prevCountA1.Set(actualCountA1)

			// Contract 2, countA
			_, incErr = integration.IncrementCount(contract2.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA2.Add(actualCountA2, big.NewInt(1))

			countA2AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2AfterIncrement := new(big.Int).SetBytes(countA2AfterIncrementStorage)
			Expect(countA2AfterIncrement.String()).To(Equal(actualCountA2.String()))
			prevCountA2.Set(actualCountA2)

			// Contract 3, countA
			_, incErr = integration.IncrementCount(contract3.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA3.Add(actualCountA3, big.NewInt(1))

			countA3AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3AfterIncrement := new(big.Int).SetBytes(countA3AfterIncrementStorage)
			Expect(countA3AfterIncrement.String()).To(Equal(prevCountA3.String()))
		})
	})

	Context("contract removed from the watch-list", func() {
		It("indexes state only for the watched contract", func() {
			operation := sdtypes.Remove
			args := []sdtypes.WatchAddressArg{
				{
					Address:   contract1.Address,
					CreatedAt: uint64(contract1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// WatchedAddresses = [Contract2]
			// Send eth to all three contract accounts
			// Contract 1
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(prevBalance1.String()))

			// Contract 2
			_, txErr = integration.SendEth(contract2.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			// Contract 3
			_, txErr = integration.SendEth(contract3.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(prevBalance3.String()))

			// Increment counts
			// Contract 1, countA
			_, incErr = integration.IncrementCount(contract1.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA1.Add(actualCountA1, big.NewInt(1))

			countA1AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1AfterIncrement := new(big.Int).SetBytes(countA1AfterIncrementStorage)
			Expect(countA1AfterIncrement.String()).To(Equal(prevCountA1.String()))

			// Contract 2, countA
			_, incErr = integration.IncrementCount(contract2.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA2.Add(actualCountA2, big.NewInt(1))

			countA2AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2AfterIncrement := new(big.Int).SetBytes(countA2AfterIncrementStorage)
			Expect(countA2AfterIncrement.String()).To(Equal(actualCountA2.String()))
			prevCountA2.Set(actualCountA2)

			// Contract 3, countA
			_, incErr = integration.IncrementCount(contract3.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA3.Add(actualCountA3, big.NewInt(1))

			countA3AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3AfterIncrement := new(big.Int).SetBytes(countA3AfterIncrementStorage)
			Expect(countA3AfterIncrement.String()).To(Equal(prevCountA3.String()))
		})
	})

	Context("list of watched addresses set", func() {
		It("indexes state only for the watched contracts", func() {
			operation := sdtypes.Set
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

			// WatchedAddresses = [Contract1, Contract3]
			// Send eth to all three contract accounts
			// Contract 1
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			// Contract 2
			_, txErr = integration.SendEth(contract2.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(prevBalance2.String()))

			// Contract 3
			_, txErr = integration.SendEth(contract3.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(actualBalance3.String()))
			prevBalance3.Set(actualBalance3)

			// Increment counts
			// Contract 1, countA
			_, incErr = integration.IncrementCount(contract1.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA1.Add(actualCountA1, big.NewInt(1))

			countA1AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1AfterIncrement := new(big.Int).SetBytes(countA1AfterIncrementStorage)
			Expect(countA1AfterIncrement.String()).To(Equal(actualCountA1.String()))
			prevCountA1.Set(actualCountA1)

			// Contract 2, countA
			_, incErr = integration.IncrementCount(contract2.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA2.Add(actualCountA2, big.NewInt(1))

			countA2AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2AfterIncrement := new(big.Int).SetBytes(countA2AfterIncrementStorage)
			Expect(countA2AfterIncrement.String()).To(Equal(prevCountA2.String()))

			// Contract 3, countA
			_, incErr = integration.IncrementCount(contract3.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA3.Add(actualCountA3, big.NewInt(1))

			countA3AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3AfterIncrement := new(big.Int).SetBytes(countA3AfterIncrementStorage)
			Expect(countA3AfterIncrement.String()).To(Equal(actualCountA3.String()))
			prevCountA3.Set(actualCountA3)
		})
	})

	Context("list of watched addresses cleared", func() {
		It("indexes state for all the contracts", func() {
			operation := sdtypes.Clear
			args := []sdtypes.WatchAddressArg{}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// WatchedAddresses = []
			// Send eth to all three contract accounts
			// Contract 1
			_, txErr = integration.SendEth(contract1.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance1.Add(actualBalance1, big.NewInt(10000000000000000))

			balance1AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract1.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance1AfterTransfer.String()).To(Equal(actualBalance1.String()))
			prevBalance1.Set(actualBalance1)

			// Contract 2
			_, txErr = integration.SendEth(contract2.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance2.Add(actualBalance2, big.NewInt(10000000000000000))

			balance2AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract2.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance2AfterTransfer.String()).To(Equal(actualBalance2.String()))
			prevBalance2.Set(actualBalance2)

			// Contract 3
			_, txErr = integration.SendEth(contract3.Address, "0.01")
			time.Sleep(sleepInterval)
			Expect(txErr).ToNot(HaveOccurred())
			actualBalance3.Add(actualBalance3, big.NewInt(10000000000000000))

			balance3AfterTransfer, err := ipldClient.BalanceAt(ctx, common.HexToAddress(contract3.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(balance3AfterTransfer.String()).To(Equal(actualBalance3.String()))
			prevBalance3.Set(actualBalance3)

			// Increment counts
			// Contract 1, countA
			_, incErr = integration.IncrementCount(contract1.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA1.Add(actualCountA1, big.NewInt(1))

			countA1AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1AfterIncrement := new(big.Int).SetBytes(countA1AfterIncrementStorage)
			Expect(countA1AfterIncrement.String()).To(Equal(actualCountA1.String()))
			prevCountA1.Set(actualCountA1)

			// Contract 2, countA
			_, incErr = integration.IncrementCount(contract2.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA2.Add(actualCountA2, big.NewInt(1))

			countA2AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2AfterIncrement := new(big.Int).SetBytes(countA2AfterIncrementStorage)
			Expect(countA2AfterIncrement.String()).To(Equal(actualCountA2.String()))
			prevCountA2.Set(actualCountA2)

			// Contract 3, countA
			_, incErr = integration.IncrementCount(contract3.Address, "A")
			time.Sleep(sleepInterval)
			Expect(incErr).ToNot(HaveOccurred())
			actualCountA3.Add(actualCountA3, big.NewInt(1))

			countA3AfterIncrementStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3AfterIncrement := new(big.Int).SetBytes(countA3AfterIncrementStorage)
			Expect(countA3AfterIncrement.String()).To(Equal(actualCountA3.String()))
			prevCountA3.Set(actualCountA3)
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
			operation := sdtypes.Add
			args := []string{"WrongArg"}

			gethErr := gethRPCClient.Call(nil, gethMethod, operation, args)
			Expect(gethErr).To(HaveOccurred())

			ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
			Expect(ipldErr).To(HaveOccurred())

			Expect(ipldErr).To(Equal(gethErr))
		})
	})
})
