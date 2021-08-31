package serve

import (
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff/indexer/node"
	"github.com/spf13/viper"
)

// Env variables
const (
	HTTPTimeout = "HTTP_TIMEOUT"

	EthWsPath       = "ETH_WS_PATH"
	ethHTTPPath     = "ETH_HTTP_PATH"
	ethNodeID       = "ETH_NODE_ID"
	ethClientName   = "ETH_CLIENT_NAME"
	ethGenesisBlock = "ETH_GENESIS_BLOCK"
	ethNetworkID    = "ETH_NETWORK_ID"
	ethChainID      = "ETH_CHAIN_ID"

	databaseName                = "DATABASE_NAME"
	databaseHostname            = "DATABASE_HOSTNAME"
	databasePort                = "DATABASE_PORT"
	databaseUser                = "DATABASE_USER"
	databasePassword            = "DATABASE_PASSWORD"
	databaseMaxIdleConnections  = "DATABASE_MAX_IDLE_CONNECTIONS"
	databaseMaxOpenConnections  = "DATABASE_MAX_OPEN_CONNECTIONS"
	databaseMaxOpenConnLifetime = "DATABASE_MAX_CONN_LIFETIME"
)

// GetEthNodeAndClient returns eth node info and client from path url
func getEthNodeAndClient(path string) (node.Info, *rpc.Client, error) {
	viper.BindEnv("ethereum.nodeID", ethNodeID)
	viper.BindEnv("ethereum.clientName", ethClientName)
	viper.BindEnv("ethereum.genesisBlock", ethGenesisBlock)
	viper.BindEnv("ethereum.networkID", ethNetworkID)
	viper.BindEnv("ethereum.chainID", ethChainID)

	rpcClient, err := rpc.Dial(path)
	if err != nil {
		return node.Info{}, nil, err
	}
	return node.Info{
		ID:           viper.GetString("ethereum.nodeID"),
		ClientName:   viper.GetString("ethereum.clientName"),
		GenesisBlock: viper.GetString("ethereum.genesisBlock"),
		NetworkID:    viper.GetString("ethereum.networkID"),
		ChainID:      viper.GetUint64("ethereum.chainID"),
	}, rpcClient, nil
}
