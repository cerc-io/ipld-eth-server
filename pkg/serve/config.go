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
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/params"
	"github.com/spf13/viper"
	"github.com/vulcanize/ipld-eth-indexer/pkg/node"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/utils"

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

	ETH_CHAIN_ID = "ETH_CHAIN_ID"

	ETH_DEFAULT_SENDER_ADDR = "ETH_DEFAULT_SENDER_ADDR"

	ETH_RPC_GAS_CAP = "ETH_RPC_GAS_CAP"
)

// Config struct
type Config struct {
	DB            *postgres.DB
	DBConfig      postgres.Config
	WSEndpoint    string
	HTTPEndpoint  string
	IPCEndpoint   string
	ChainConfig   *params.ChainConfig
	DefaultSender *common.Address
	RPCGasCap     *big.Int
}

// NewConfig is used to initialize a watcher config from a .toml file
// Separate chain watcher instances need to be ran with separate ipfs path in order to avoid lock contention on the ipfs repository lockfile
func NewConfig() (*Config, error) {
	c := new(Config)

	viper.BindEnv("server.wsPath", SERVER_WS_PATH)
	viper.BindEnv("server.ipcPath", SERVER_IPC_PATH)
	viper.BindEnv("server.httpPath", SERVER_HTTP_PATH)
	viper.BindEnv("ethereum.chainID", ETH_CHAIN_ID)
	viper.BindEnv("ethereum.defaultSender", ETH_DEFAULT_SENDER_ADDR)
	viper.BindEnv("ethereum.rpcGasCap", ETH_RPC_GAS_CAP)

	c.DBConfig.Init()

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
	overrideDBConnConfig(&c.DBConfig)
	serveDB := utils.LoadPostgres(c.DBConfig, node.Info{})
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
	chainID := viper.GetUint64("ethereum.chainID")
	var err error
	c.ChainConfig, err = eth.ChainConfig(chainID)
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
