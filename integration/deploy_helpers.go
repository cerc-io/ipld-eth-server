package integration

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff/types"
)

type ContractDeployed struct {
	Address         common.Address `json:"address"`
	TransactionHash common.Hash    `json:"txHash"`
	BlockNumber     int64          `json:"blockNumber"`
	BlockHash       common.Hash    `json:"blockHash"`
}

type ContractDestroyed struct {
	BlockNumber int64 `json:"blockNumber"`
}

type Tx struct {
	From            string   `json:"from"`
	To              string   `json:"to"`
	Value           *big.Int `json:"value"`
	TransactionHash string   `json:"txHash"`
	BlockNumber     int64    `json:"blockNumber"`
	BlockHash       string   `json:"blockHash"`
}

type StorageKey struct {
	Key string `json:"key"`
}

type CountIncremented struct {
	BlockNumber *big.Int `json:"blockNumber"`
}

const ContractServerUrl = "http://localhost:3000"

// Factory which creates endpoint functions
func MakeGetAndDecodeFunc[R any](format string) func(...interface{}) (*R, error) {
	return func(params ...interface{}) (*R, error) {
		params = append([]interface{}{ContractServerUrl}, params...)
		url := fmt.Sprintf(format, params...)
		res, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", url, res.Status)
		}

		var data R
		decoder := json.NewDecoder(res.Body)
		return &data, decoder.Decode(&data)
	}
}

var (
	DeployContract     = MakeGetAndDecodeFunc[ContractDeployed]("%s/v1/deployContract")
	DestroyContract    = MakeGetAndDecodeFunc[ContractDestroyed]("%s/v1/destroyContract?addr=%s")
	DeploySLVContract  = MakeGetAndDecodeFunc[ContractDeployed]("%s/v1/deploySLVContract")
	DestroySLVContract = MakeGetAndDecodeFunc[ContractDestroyed]("%s/v1/destroySLVContract?addr=%s")
	SendEth            = MakeGetAndDecodeFunc[Tx]("%s/v1/sendEth?to=%s&value=%s")
	GetStorageSlotKey  = MakeGetAndDecodeFunc[StorageKey]("%s/v1/getStorageKey?contract=%s&label=%s")
	IncrementCount     = MakeGetAndDecodeFunc[CountIncremented]("%s/v1/incrementCount%s?addr=%s")
	Create2Contract    = MakeGetAndDecodeFunc[ContractDeployed]("%s/v1/create2Contract?contract=%s&salt=%s")
)

func ClearWatchedAddresses(gethRPCClient *rpc.Client) error {
	gethMethod := "statediff_watchAddress"
	args := []types.WatchAddressArg{}

	// Clear watched addresses
	return gethRPCClient.Call(nil, gethMethod, types.Clear, args)
}
