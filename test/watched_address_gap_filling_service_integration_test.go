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
	"github.com/ethereum/go-ethereum/statediff"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	integration "github.com/vulcanize/ipld-eth-server/test"
)

var _ = Describe("Watched address gap filling service integration test", func() {
	dbWrite, err := strconv.ParseBool(os.Getenv("DB_WRITE"))
	Expect(err).To(BeNil())

	watchedAddressServiceEnabled, err := strconv.ParseBool(os.Getenv("WATCHED_ADDRESS_GAP_FILLER_ENABLED"))
	Expect(err).To(BeNil())

	serviceInterval, err := strconv.ParseInt(os.Getenv("WATCHED_ADDRESS_GAP_FILLER_INTERVAL"), 10, 0)
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

		contractErr error
		txErr       error

		GLD1 *integration.ContractDeployed
		SLV1 *integration.ContractDeployed
		SLV2 *integration.ContractDeployed

		countAIndex string
		countBIndex string

		oldCountA1 = big.NewInt(0)
		oldCountA2 = big.NewInt(0)
		oldCountB2 = big.NewInt(0)

		updatedCountA1 = big.NewInt(1)
		updatedCountA2 = big.NewInt(1)
		updatedCountB2 = big.NewInt(1)

		SLV2CountBIncrementedAt *integration.CountIncremented
	)

	BeforeEach(func() {
		if !dbWrite || !watchedAddressServiceEnabled {
			Skip("skipping watched address gap filling service integration tests")
		}
	})

	It("test init", func() {
		// Clear out watched addresses
		err := integration.ClearWatchedAddresses(gethRPCClient)
		Expect(err).ToNot(HaveOccurred())

		// Deploy a GLD contract
		GLD1, contractErr = integration.DeployContract()
		Expect(contractErr).ToNot(HaveOccurred())

		// Watch GLD1 contract
		operation := statediff.Add
		args := []sdtypes.WatchAddressArg{
			{
				Address:   GLD1.Address,
				CreatedAt: uint64(GLD1.BlockNumber),
			},
		}
		ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
		Expect(ipldErr).ToNot(HaveOccurred())

		// Deploy two SLV contracts and update storage slots
		SLV1, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		_, txErr = integration.IncrementCount(SLV1.Address, "A")
		Expect(txErr).ToNot(HaveOccurred())

		SLV2, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		_, txErr = integration.IncrementCount(SLV2.Address, "A")
		Expect(txErr).ToNot(HaveOccurred())
		SLV2CountBIncrementedAt, txErr = integration.IncrementCount(SLV2.Address, "B")
		Expect(txErr).ToNot(HaveOccurred())

		// Get storage slot keys
		storageSlotAKey, err := integration.GetStorageSlotKey("SLVToken", "countA")
		Expect(err).ToNot(HaveOccurred())
		countAIndex = storageSlotAKey.Key

		storageSlotBKey, err := integration.GetStorageSlotKey("SLVToken", "countB")
		Expect(err).ToNot(HaveOccurred())
		countBIndex = storageSlotBKey.Key
	})

	defer It("test cleanup", func() {
		// Clear out watched addresses
		err := integration.ClearWatchedAddresses(gethRPCClient)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("previously unwatched contract watched", func() {
		It("indexes state only for watched contract", func() {
			// WatchedAddresses = [GLD1]
			// SLV1, countA
			countA1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1 := new(big.Int).SetBytes(countA1Storage)
			Expect(countA1.String()).To(Equal(oldCountA1.String()))

			// SLV2, countA
			countA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2 := new(big.Int).SetBytes(countA2Storage)
			Expect(countA2.String()).To(Equal(oldCountA2.String()))

			// SLV2, countB
			countB2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB2 := new(big.Int).SetBytes(countB2Storage)
			Expect(countB2.String()).To(Equal(oldCountB2.String()))
		})

		It("indexes past state on watching a contract", func() {
			// Watch SLV1 contract
			args := []sdtypes.WatchAddressArg{
				{
					Address:   SLV1.Address,
					CreatedAt: uint64(SLV1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.Add, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// WatchedAddresses = [GLD1, SLV1]
			// SLV1, countA
			countA1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1 := new(big.Int).SetBytes(countA1Storage)
			Expect(countA1.String()).To(Equal(updatedCountA1.String()))

			// SLV2, countA
			countA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2 := new(big.Int).SetBytes(countA2Storage)
			Expect(countA2.String()).To(Equal(oldCountA2.String()))

			// SLV2, countB
			countB2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB2 := new(big.Int).SetBytes(countB2Storage)
			Expect(countB2.String()).To(Equal(oldCountB2.String()))
		})
	})

	Context("previously unwatched contract watched (different 'created_at')", func() {
		It("indexes past state from 'created_at' onwards on watching a contract", func() {
			// Watch SLV2 (created_at -> countB incremented) contract
			args := []sdtypes.WatchAddressArg{
				{
					Address:   SLV2.Address,
					CreatedAt: uint64(SLV2CountBIncrementedAt.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.Add, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// WatchedAddresses = [GLD1, SLV1, SLV2]
			// SLV2, countA
			countA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2 := new(big.Int).SetBytes(countA2Storage)
			Expect(countA2.String()).To(Equal(oldCountA2.String()))

			// SLV2, countB
			countB2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB2 := new(big.Int).SetBytes(countB2Storage)
			Expect(countB2.String()).To(Equal(updatedCountB2.String()))
		})

		It("indexes missing past state on watching a contract from an earlier 'created_at'", func() {
			// Clear out watched addresses
			err := integration.ClearWatchedAddresses(gethRPCClient)
			Expect(err).ToNot(HaveOccurred())

			// Watch SLV2 (created_at -> deployment) contract
			args := []sdtypes.WatchAddressArg{
				{
					Address:   SLV2.Address,
					CreatedAt: uint64(SLV2.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.Add, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// WatchedAddresses = [SLV2]
			// SLV2, countA
			countA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2 := new(big.Int).SetBytes(countA2Storage)
			Expect(countA2.String()).To(Equal(updatedCountA2.String()))

			// SLV2, countB
			countB2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB2 := new(big.Int).SetBytes(countB2Storage)
			Expect(countB2.String()).To(Equal(updatedCountB2.String()))
		})
	})
})
