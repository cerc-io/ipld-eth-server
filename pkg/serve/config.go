// VulcanizeDB
// Copyright © 2019 Vulcanize

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package serve

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/viper"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"
	"github.com/vulcanize/ipld-eth-indexer/utils"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
)

// Env variables
const (
	SERVER_WS_PATH   = "SERVER_WS_PATH"
	SERVER_IPC_PATH  = "SERVER_IPC_PATH"
	SERVER_HTTP_PATH = "SERVER_HTTP_PATH"

	SERVER_MAX_IDLE_CONNECTIONS = "SERVER_MAX_IDLE_CONNECTIONS"
	SERVER_MAX_OPEN_CONNECTIONS = "SERVER_MAX_OPEN_CONNECTIONS"
	SERVER_MAX_CONN_LIFETIME    = "SERVER_MAX_CONN_LIFETIME"

	ETH_DEFAULT_SENDER_ADDR = "ETH_DEFAULT_SENDER_ADDR"
	ETH_RPC_GAS_CAP         = "ETH_RPC_GAS_CAP"
	ETH_CHAIN_CONFIG        = "ETH_CHAIN_CONFIG"
	ETH_SUPPORTS_STATEDIFF  = "ETH_SUPPORTS_STATEDIFF"
)

// Config struct
type Config struct {
	DB               *postgres.DB
	WSEndpoint       string
	HTTPEndpoint     string
	IPCEndpoint      string
	ChainConfig      *params.ChainConfig
	DefaultSender    *common.Address
	RPCGasCap        *big.Int
	Client           *rpc.Client
	SupportStateDiff bool
}

// NewConfig is used to initialize a watcher config from a .toml file
// Separate chain watcher instances need to be ran with separate ipfs path in order to avoid lock contention on the ipfs repository lockfile
func NewConfig() (*Config, error) {
	c := new(Config)

	viper.BindEnv("server.wsPath", SERVER_WS_PATH)
	viper.BindEnv("server.ipcPath", SERVER_IPC_PATH)
	viper.BindEnv("server.httpPath", SERVER_HTTP_PATH)
	viper.BindEnv("ethereum.httpPath", shared.ETH_HTTP_PATH)
	viper.BindEnv("ethereum.defaultSender", ETH_DEFAULT_SENDER_ADDR)
	viper.BindEnv("ethereum.rpcGasCap", ETH_RPC_GAS_CAP)
	viper.BindEnv("ethereum.chainConfig", ETH_CHAIN_CONFIG)
	viper.BindEnv("ethereum.supportsStateDiff", ETH_SUPPORTS_STATEDIFF)

	dbConfig := postgres.NewConfig()

	ethHTTP := viper.GetString("ethereum.httpPath")
	nodeInfo, cli, err := shared.GetEthNodeAndClient(fmt.Sprintf("http://%s", ethHTTP))
	if err != nil {
		return nil, err
	}
	c.Client = cli
	c.SupportStateDiff = viper.GetBool("ethereum.supportsStateDiff")

	wsPath := viper.GetString("server.wsPath")
	if wsPath == "" {
		wsPath = "127.0.0.1:8080"
	}
	c.WSEndpoint = wsPath
	ipcPath := viper.GetString("server.ipcPath")
	if ipcPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		ipcPath = filepath.Join(home, ".vulcanize/vulcanize.ipc")
	}
	c.IPCEndpoint = ipcPath
	httpPath := viper.GetString("server.httpPath")
	if httpPath == "" {
		httpPath = "127.0.0.1:8081"
	}
	c.HTTPEndpoint = httpPath
	overrideDBConnConfig(dbConfig)
	serveDB := utils.LoadPostgres(dbConfig, nodeInfo, false)
	prom.RegisterDBCollector(dbConfig.Name, serveDB.DB)
	c.DB = &serveDB

	defaultSenderStr := viper.GetString("ethereum.defaultSender")
	if defaultSenderStr != "" {
		sender := common.HexToAddress(defaultSenderStr)
		c.DefaultSender = &sender
	}
	rpcGasCapStr := viper.GetString("ethereum.rpcGasCap")
	if rpcGasCapStr != "" {
		if rpcGasCap, ok := new(big.Int).SetString(rpcGasCapStr, 10); ok {
			c.RPCGasCap = rpcGasCap
		}
	}
	chainConfigPath := viper.GetString("ethereum.chainConfig")
	if chainConfigPath != "" {
		c.ChainConfig, err = eth.LoadConfig(chainConfigPath)
	} else {
		c.ChainConfig, err = eth.ChainConfig(nodeInfo.ChainID)
	}
	return c, err
}

func overrideDBConnConfig(con *postgres.Config) {
	viper.BindEnv("database.server.maxIdle", SERVER_MAX_IDLE_CONNECTIONS)
	viper.BindEnv("database.server.maxOpen", SERVER_MAX_OPEN_CONNECTIONS)
	viper.BindEnv("database.server.maxLifetime", SERVER_MAX_CONN_LIFETIME)
	con.MaxIdle = viper.GetInt("database.server.maxIdle")
	con.MaxOpen = viper.GetInt("database.server.maxOpen")
	con.MaxLifetime = viper.GetInt("database.server.maxLifetime")
}
