package integration

import (
	"encoding/json"
	"net/http"
)

type ContractDeployed struct {
	Address         string
	TransactionHash string
	BlockNumber     int
	BlockHash       string
}

func DeployContract() (*ContractDeployed, error) {
	res, err := http.Get("http://localhost:3000/v1/deployContract")
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
