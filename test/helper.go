package integration

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/rpc"
	sdtypes "github.com/ethereum/go-ethereum/statediff/types"

	"github.com/ethereum/go-ethereum/statediff"
)

type ContractDeployed struct {
	Address         string `json:"address"`
	TransactionHash string `json:"txHash"`
	BlockNumber     int    `json:"blockNumber"`
	BlockHash       string `json:"blockHash"`
}

type ContractDestroyed struct {
	BlockNumber int64 `json:"blockNumber"`
}

type Tx struct {
	From            string   `json:"from"`
	To              string   `json:"to"`
	Value           *big.Int `json:"value"`
	TransactionHash string   `json:"txHash"`
	BlockNumber     int      `json:"blockNumber"`
	BlockHash       string   `json:"blockHash"`
}

type StorageKey struct {
	Key string `json:"key"`
}

const srvUrl = "http://localhost:3000"

func DeployContract() (*ContractDeployed, error) {
	res, err := http.Get(fmt.Sprintf("%s/v1/deployContract", srvUrl))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var contract ContractDeployed

	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&contract)
	if err != nil {
		return nil, err
	}

	return &contract, nil
}

func DestroyContract(addr string) (*ContractDestroyed, error) {
	res, err := http.Get(fmt.Sprintf("%s/v1/destroyContract?addr=%s", srvUrl, addr))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var data ContractDestroyed
	decoder := json.NewDecoder(res.Body)

	return &data, decoder.Decode(&data)
}

func SendEth(to string, value string) (*Tx, error) {
	res, err := http.Get(fmt.Sprintf("%s/v1/sendEth?to=%s&value=%s", srvUrl, to, value))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var tx Tx

	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&tx)
	if err != nil {
		return nil, err
	}

	return &tx, nil
}

func DeploySLVContract() (*ContractDeployed, error) {
	res, err := http.Get(fmt.Sprintf("%s/v1/deploySLVContract", srvUrl))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var contract ContractDeployed

	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&contract)
	if err != nil {
		return nil, err
	}

	return &contract, nil
}

func IncrementCountA(addr string) error {
	_, err := http.Get(fmt.Sprintf("%s/v1/incrementCountA?addr=%s", srvUrl, addr))
	if err != nil {
		return err
	}

	return nil
}

func IncrementCountB(addr string) error {
	_, err := http.Get(fmt.Sprintf("%s/v1/incrementCountB?addr=%s", srvUrl, addr))
	if err != nil {
		return err
	}

	return nil
}

func GetStorageSlotKey(contract string, label string) (*StorageKey, error) {
	res, err := http.Get(fmt.Sprintf("%s/v1/getStorageKey?contract=%s&label=%s", srvUrl, contract, label))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var key StorageKey

	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&key)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

func ClearWatchedAddresses(gethRPCClient *rpc.Client) error {
	gethMethod := "statediff_watchAddress"
	args := []sdtypes.WatchAddressArg{}

	// Clear watched addresses
	gethErr := gethRPCClient.Call(nil, gethMethod, statediff.ClearAddresses, args)
	if gethErr != nil {
		return gethErr
	}

	// Clear watched storage slots
	gethErr = gethRPCClient.Call(nil, gethMethod, statediff.ClearStorageSlots, args)
	if gethErr != nil {
		return gethErr
	}

	return nil
}
