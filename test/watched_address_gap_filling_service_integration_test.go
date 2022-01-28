package integration_test

import (
	"context"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	integration "github.com/vulcanize/ipld-eth-server/test"
)

var (
	ctx = context.Background()

	ipldClient *ethclient.Client
)

var _ = Describe("Watched address gap filling service integration test", func() {
	dbWrite, err := strconv.ParseBool(os.Getenv("DB_WRITE"))
	Expect(err).To(BeNil())

	serviceEnabled, err := strconv.ParseBool(os.Getenv("WATCHED_ADDRESS_GAP_FILLER_ENABLED"))
	Expect(err).To(BeNil())

	serviceInterval, err := strconv.ParseInt(os.Getenv("WATCHED_ADDRESS_GAP_FILLER_INTERVAL"), 10, 0)
	Expect(err).To(BeNil())

	gethHttpPath := "http://127.0.0.1:8545"
	gethRPCClient, err := rpc.Dial(gethHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ipldEthHttpPath := "http://127.0.0.1:8081"
	ipldClient, err = ethclient.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())
	ipldRPCClient, err := rpc.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())

	var (
		contractErr error
		txErr       error

		GLD1 *integration.ContractDeployed
		GLD2 *integration.ContractDeployed
		SLV1 *integration.ContractDeployed
		SLV2 *integration.ContractDeployed
		SLV3 *integration.ContractDeployed

		countAIndex       string
		countBIndex       string
		countAStorageHash common.Hash
		countBStorageHash common.Hash

		totalSupplyIndex      = "0x2"
		totalSuppyStorageHash = crypto.Keccak256Hash(common.HexToHash(totalSupplyIndex).Bytes())

		oldCountA1 = big.NewInt(0)
		oldCountB1 = big.NewInt(0)
		oldCountA2 = big.NewInt(0)
		oldCountB2 = big.NewInt(0)
		oldCountA3 = big.NewInt(0)
		oldCountB3 = big.NewInt(0)

		updatedCountA1 = big.NewInt(1)
		updatedCountB1 = big.NewInt(1)
		updatedCountA2 = big.NewInt(1)
		updatedCountB2 = big.NewInt(1)
		updatedCountA3 = big.NewInt(1)
		updatedCountB3 = big.NewInt(1)
	)

	BeforeEach(func() {
		if !dbWrite || !serviceEnabled {
			Skip("skipping WatchAddress integration tests")
		}
	})

	It("test init", func() {
		// Clear out watched addresses | storage slots
		err := integration.ClearWatchedAddresses(gethRPCClient)
		Expect(err).ToNot(HaveOccurred())

		// Deploy a GLD contract
		GLD1, contractErr = integration.DeployContract()
		Expect(contractErr).ToNot(HaveOccurred())

		// Watch GLD1 contract
		operation := statediff.AddAddresses
		args := []sdtypes.WatchAddressArg{
			{
				Address:   GLD1.Address,
				CreatedAt: uint64(GLD1.BlockNumber),
			},
		}
		ipldErr := ipldRPCClient.Call(nil, ipldMethod, operation, args)
		Expect(ipldErr).ToNot(HaveOccurred())

		// Deploy a GLD contract
		GLD2, contractErr = integration.DeployContract()
		Expect(contractErr).ToNot(HaveOccurred())

		// Deploy three SLV contracts and update storage slots
		SLV1, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		txErr = integration.IncrementCountA(SLV1.Address)
		Expect(txErr).ToNot(HaveOccurred())
		txErr = integration.IncrementCountB(SLV1.Address)
		Expect(txErr).ToNot(HaveOccurred())

		SLV2, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		txErr = integration.IncrementCountA(SLV2.Address)
		Expect(txErr).ToNot(HaveOccurred())
		txErr = integration.IncrementCountB(SLV2.Address)
		Expect(txErr).ToNot(HaveOccurred())

		SLV3, contractErr = integration.DeploySLVContract()
		Expect(contractErr).ToNot(HaveOccurred())

		txErr = integration.IncrementCountA(SLV3.Address)
		Expect(txErr).ToNot(HaveOccurred())
		txErr = integration.IncrementCountB(SLV3.Address)
		Expect(txErr).ToNot(HaveOccurred())

		// Get storage slot keys
		storageSlotAKey, err := integration.GetStorageSlotKey("SLVToken", "countA")
		Expect(err).ToNot(HaveOccurred())
		countAIndex = storageSlotAKey.Key
		countAStorageHash = crypto.Keccak256Hash(common.HexToHash(countAIndex).Bytes())

		storageSlotBKey, err := integration.GetStorageSlotKey("SLVToken", "countB")
		Expect(err).ToNot(HaveOccurred())
		countBIndex = storageSlotBKey.Key
		countBStorageHash = crypto.Keccak256Hash(common.HexToHash(countBIndex).Bytes())
	})

	defer It("test cleanup", func() {
		// Clear out watched addresses | storage slots
		err := integration.ClearWatchedAddresses(gethRPCClient)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("previously unwatched contract watched", func() {
		It("indexes state only for watched contract", func() {
			// SLV1, countA
			countA1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1 := new(big.Int).SetBytes(countA1Storage)
			Expect(countA1.String()).To(Equal(oldCountA1.String()))

			// SLV1, countB
			countB1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV1.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB1 := new(big.Int).SetBytes(countB1Storage)
			Expect(countB1.String()).To(Equal(oldCountB1.String()))

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

			// SLV3, countA
			countA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3 := new(big.Int).SetBytes(countA3Storage)
			Expect(countA3.String()).To(Equal(oldCountA3.String()))

			// SLV3, countB
			countB3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB3 := new(big.Int).SetBytes(countB3Storage)
			Expect(countB3.String()).To(Equal(oldCountB3.String()))
		})

		It("indexes past state on watching a contract", func() {
			// Watch SLV1 contract
			args := []sdtypes.WatchAddressArg{
				{
					Address:   SLV1.Address,
					CreatedAt: uint64(SLV1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.AddAddresses, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// SLV1, countA
			countA1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV1.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA1 := new(big.Int).SetBytes(countA1Storage)
			Expect(countA1.String()).To(Equal(updatedCountA1.String()))

			// SLV1, countB
			countB1Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV1.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB1 := new(big.Int).SetBytes(countB1Storage)
			Expect(countB1.String()).To(Equal(updatedCountB1.String()))

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

			// SLV3, countA
			countA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3 := new(big.Int).SetBytes(countA3Storage)
			Expect(countA3.String()).To(Equal(oldCountA3.String()))

			// SLV3, countB
			countB3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB3 := new(big.Int).SetBytes(countB3Storage)
			Expect(countB3.String()).To(Equal(oldCountB3.String()))
		})
	})

	Context("one storage slot being watched", func() {
		It("indexer past state only for watched storage slots of watched contracts", func() {
			// Watch countA
			args := []sdtypes.WatchAddressArg{
				{
					Address:   countAStorageHash.Hex(),
					CreatedAt: uint64(SLV1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.AddStorageSlots, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Watch SLV2 contract
			args = []sdtypes.WatchAddressArg{
				{
					Address:   SLV2.Address,
					CreatedAt: uint64(SLV2.BlockNumber),
				},
			}
			ipldErr = ipldRPCClient.Call(nil, ipldMethod, statediff.AddAddresses, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// SLV2, countA
			countA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2 := new(big.Int).SetBytes(countA2Storage)
			Expect(countA2.String()).To(Equal(updatedCountA2.String()))

			// SLV2, countB
			countB2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB2 := new(big.Int).SetBytes(countB2Storage)
			Expect(countB2.String()).To(Equal(oldCountB2.String()))

			// SLV3, countA
			countA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3 := new(big.Int).SetBytes(countA3Storage)
			Expect(countA3.String()).To(Equal(oldCountA3.String()))

			// SLV3, countB
			countB3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB3 := new(big.Int).SetBytes(countB3Storage)
			Expect(countB3.String()).To(Equal(oldCountB3.String()))
		})
	})

	Context("previously unwatched storage slot watched", func() {
		It("indexes past state only for watched storage slots updated after created at", func() {
			// Watch countB
			args := []sdtypes.WatchAddressArg{
				{
					Address:   countBStorageHash.Hex(),
					CreatedAt: uint64(SLV3.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.AddStorageSlots, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// SLV2, countA
			countA2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA2 := new(big.Int).SetBytes(countA2Storage)
			Expect(countA2.String()).To(Equal(updatedCountA2.String()))

			// SLV2, countB
			countB2Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV2.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB2 := new(big.Int).SetBytes(countB2Storage)
			Expect(countB2.String()).To(Equal(oldCountB2.String()))

			// SLV3, countA
			countA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3 := new(big.Int).SetBytes(countA3Storage)
			Expect(countA3.String()).To(Equal(oldCountA3.String()))

			// SLV3, countB
			countB3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB3 := new(big.Int).SetBytes(countB3Storage)
			Expect(countB3.String()).To(Equal(oldCountB3.String()))
		})

		It("indexes past state for watched storage slots of watched contracts", func() {
			// Watch countB
			args := []sdtypes.WatchAddressArg{
				{
					Address:   countBStorageHash.Hex(),
					CreatedAt: uint64(SLV1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.AddStorageSlots, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

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

			// SLV3, countA
			countA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3 := new(big.Int).SetBytes(countA3Storage)
			Expect(countA3.String()).To(Equal(oldCountA3.String()))

			// SLV3, countB
			countB3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB3 := new(big.Int).SetBytes(countB3Storage)
			Expect(countB3.String()).To(Equal(oldCountB3.String()))
		})
	})

	Context("contract watched along with other contract and its storage slots", func() {
		It("indexes past state for watched storage slots of watched contracts", func() {
			// Watch totalSupply
			args := []sdtypes.WatchAddressArg{
				{
					Address:   totalSuppyStorageHash.Hex(),
					CreatedAt: uint64(GLD1.BlockNumber),
				},
			}
			ipldErr := ipldRPCClient.Call(nil, ipldMethod, statediff.AddStorageSlots, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Watch GLD2 and SLV3 contracts
			args = []sdtypes.WatchAddressArg{
				{
					Address:   GLD2.Address,
					CreatedAt: uint64(GLD2.BlockNumber),
				},
				{
					Address:   SLV3.Address,
					CreatedAt: uint64(SLV3.BlockNumber),
				},
			}
			ipldErr = ipldRPCClient.Call(nil, ipldMethod, statediff.AddAddresses, args)
			Expect(ipldErr).ToNot(HaveOccurred())

			// Sleep for service interval + few extra seconds
			time.Sleep(time.Duration(serviceInterval+2) * time.Second)

			// SLV3, countA
			countA3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countAIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countA3 := new(big.Int).SetBytes(countA3Storage)
			Expect(countA3.String()).To(Equal(updatedCountA3.String()))

			// SLV3, countB
			countB3Storage, err := ipldClient.StorageAt(ctx, common.HexToAddress(SLV3.Address), common.HexToHash(countBIndex), nil)
			Expect(err).ToNot(HaveOccurred())
			countB3 := new(big.Int).SetBytes(countB3Storage)
			Expect(countB3.String()).To(Equal(updatedCountB3.String()))
		})
	})
})
