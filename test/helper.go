package integration

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
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

	fmt.Println(res.Body)
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
