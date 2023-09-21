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
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/cerc-io/plugeth-statediff/indexer/database/sql/postgres"
	"github.com/cerc-io/plugeth-statediff/indexer/node"
	"github.com/cerc-io/plugeth-statediff/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/prom"
	ethServerShared "github.com/cerc-io/ipld-eth-server/v5/pkg/shared"
)

// Env variables
const (
	SERVER_WS_PATH      = "SERVER_WS_PATH"
	SERVER_IPC_PATH     = "SERVER_IPC_PATH"
	SERVER_HTTP_PATH    = "SERVER_HTTP_PATH"
	SERVER_GRAPHQL_PATH = "SERVER_GRAPHQL_PATH"

	SERVER_MAX_IDLE_CONNECTIONS = "SERVER_MAX_IDLE_CONNECTIONS"
	SERVER_MAX_OPEN_CONNECTIONS = "SERVER_MAX_OPEN_CONNECTIONS"
	SERVER_MAX_CONN_LIFETIME    = "SERVER_MAX_CONN_LIFETIME"

	ETH_DEFAULT_SENDER_ADDR    = "ETH_DEFAULT_SENDER_ADDR"
	ETH_RPC_GAS_CAP            = "ETH_RPC_GAS_CAP"
	ETH_CHAIN_CONFIG           = "ETH_CHAIN_CONFIG"
	ETH_SUPPORTS_STATEDIFF     = "ETH_SUPPORTS_STATEDIFF"
	ETH_STATEDIFF_TIMEOUT      = "ETH_STATEDIFF_TIMEOUT"
	ETH_FORWARD_ETH_CALLS      = "ETH_FORWARD_ETH_CALLS"
	ETH_FORWARD_GET_STORAGE_AT = "ETH_FORWARD_GET_STORAGE_AT"
	ETH_PROXY_ON_ERROR         = "ETH_PROXY_ON_ERROR"
	ETH_GETLOGS_BLOCK_LIMIT    = "ETH_GETLOGS_BLOCK_LIMIT"

	VALIDATOR_ENABLED         = "VALIDATOR_ENABLED"
	VALIDATOR_EVERY_NTH_BLOCK = "VALIDATOR_EVERY_NTH_BLOCK"

	HTTP_TIMEOUT = "HTTP_TIMEOUT"

	ETH_WS_PATH       = "ETH_WS_PATH"
	ETH_HTTP_PATH     = "ETH_HTTP_PATH"
	ETH_NODE_ID       = "ETH_NODE_ID"
	ETH_CLIENT_NAME   = "ETH_CLIENT_NAME"
	ETH_GENESIS_BLOCK = "ETH_GENESIS_BLOCK"
	ETH_NETWORK_ID    = "ETH_NETWORK_ID"
	ETH_CHAIN_ID      = "ETH_CHAIN_ID"

	DATABASE_NAME                 = "DATABASE_NAME"
	DATABASE_HOSTNAME             = "DATABASE_HOSTNAME"
	DATABASE_PORT                 = "DATABASE_PORT"
	DATABASE_USER                 = "DATABASE_USER"
	DATABASE_PASSWORD             = "DATABASE_PASSWORD"
	DATABASE_MAX_IDLE_CONNECTIONS = "DATABASE_MAX_IDLE_CONNECTIONS"
	DATABASE_MAX_OPEN_CONNECTIONS = "DATABASE_MAX_OPEN_CONNECTIONS"
	DATABASE_MAX_CONN_LIFETIME    = "DATABASE_MAX_CONN_LIFETIME"
)

// Config struct
type Config struct {
	DB       *sqlx.DB
	DBConfig postgres.Config

	WSEnabled  bool
	WSEndpoint string

	HTTPEnabled  bool
	HTTPEndpoint string

	IPCEnabled  bool
	IPCEndpoint string

	EthGraphqlEnabled  bool
	EthGraphqlEndpoint string

	ChainConfig         *params.ChainConfig
	DefaultSender       *common.Address
	RPCGasCap           *big.Int
	EthHttpEndpoint     string
	Client              *rpc.Client
	SupportStateDiff    bool
	StateDiffTimeout    time.Duration
	ForwardEthCalls     bool
	ForwardGetStorageAt bool
	ProxyOnError        bool
	GetLogsBlockLimit   int64
	NodeNetworkID       string

	// Cache configuration.
	GroupCache *ethServerShared.GroupCacheConfig

	StateValidationEnabled       bool
	StateValidationEveryNthBlock uint64
}

// NewConfig is used to initialize a watcher config from a .toml file
// Separate chain watcher instances need to be ran with separate ipfs path in order to avoid lock contention on the ipfs repository lockfile
func NewConfig() (*Config, error) {
	c := new(Config)

	viper.BindEnv("server.httpPath", SERVER_HTTP_PATH)
	viper.BindEnv("server.wsPath", SERVER_WS_PATH)
	viper.BindEnv("server.ipcPath", SERVER_IPC_PATH)
	viper.BindEnv("server.graphqlPath", SERVER_GRAPHQL_PATH)

	viper.BindEnv("ethereum.httpPath", ETH_HTTP_PATH)
	viper.BindEnv("ethereum.rpcGasCap", ETH_RPC_GAS_CAP)
	viper.BindEnv("ethereum.chainConfig", ETH_CHAIN_CONFIG)
	viper.BindEnv("ethereum.supportsStateDiff", ETH_SUPPORTS_STATEDIFF)
	viper.BindEnv("ethereum.stateDiffTimeout", ETH_STATEDIFF_TIMEOUT)
	viper.BindEnv("ethereum.forwardEthCalls", ETH_FORWARD_ETH_CALLS)
	viper.BindEnv("ethereum.forwardGetStorageAt", ETH_FORWARD_GET_STORAGE_AT)
	viper.BindEnv("ethereum.proxyOnError", ETH_PROXY_ON_ERROR)
	viper.BindEnv("ethereum.getLogsBlockLimit", ETH_GETLOGS_BLOCK_LIMIT)
	viper.BindEnv("log.file", "LOG_FILE")
	viper.BindEnv("log.level", "LOG_LEVEL")

	c.dbInit()
	ethHTTP := viper.GetString("ethereum.httpPath")
	ethHTTPEndpoint := fmt.Sprintf("http://%s", ethHTTP)
	nodeInfo, cli, err := getEthNodeAndClient(ethHTTPEndpoint)
	c.NodeNetworkID = nodeInfo.NetworkID
	if err != nil {
		return nil, err
	}
	c.Client = cli
	c.SupportStateDiff = viper.GetBool("ethereum.supportsStateDiff")
	c.ForwardEthCalls = viper.GetBool("ethereum.forwardEthCalls")
	c.ForwardGetStorageAt = viper.GetBool("ethereum.forwardGetStorageAt")
	c.ProxyOnError = viper.GetBool("ethereum.proxyOnError")
	c.EthHttpEndpoint = ethHTTPEndpoint

	if viper.IsSet("ethereum.getLogsBlockLimit") {
		c.GetLogsBlockLimit = viper.GetInt64("ethereum.getLogsBlockLimit")
	} else {
		c.GetLogsBlockLimit = 500
	}

	// websocket server
	wsEnabled := viper.GetBool("server.ws")
	if wsEnabled {
		wsPath := viper.GetString("server.wsPath")
		if wsPath == "" {
			wsPath = "127.0.0.1:8080"
		}
		c.WSEndpoint = wsPath
	}
	c.WSEnabled = wsEnabled

	// ipc server
	ipcEnabled := viper.GetBool("server.ipc")
	if ipcEnabled {
		ipcPath := viper.GetString("server.ipcPath")
		if ipcPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			ipcPath = filepath.Join(home, ".vulcanize/vulcanize.ipc")
		}
		c.IPCEndpoint = ipcPath
	}
	c.IPCEnabled = ipcEnabled

	// http server
	httpEnabled := viper.GetBool("server.http")
	if httpEnabled {
		httpPath := viper.GetString("server.httpPath")
		if httpPath == "" {
			httpPath = "127.0.0.1:8081"
		}
		c.HTTPEndpoint = httpPath
	}
	c.HTTPEnabled = httpEnabled

	// eth graphql endpoint
	ethGraphqlEnabled := viper.GetBool("server.graphql")
	if ethGraphqlEnabled {
		ethGraphqlPath := viper.GetString("server.graphqlPath")
		if ethGraphqlPath == "" {
			ethGraphqlPath = "127.0.0.1:8082"
		}
		c.EthGraphqlEndpoint = ethGraphqlPath
	}
	c.EthGraphqlEnabled = ethGraphqlEnabled

	overrideDBConnConfig(&c.DBConfig)
	serveDB, err := ethServerShared.NewDB(c.DBConfig.DbConnectionString(), c.DBConfig)
	if err != nil {
		return nil, err
	}

	prom.RegisterDBCollector(c.DBConfig.DatabaseName, serveDB)
	c.DB = serveDB

	rpcGasCapStr := viper.GetString("ethereum.rpcGasCap")
	if rpcGasCapStr != "" {
		if rpcGasCap, ok := new(big.Int).SetString(rpcGasCapStr, 10); ok {
			c.RPCGasCap = rpcGasCap
		}
	} else {
		c.RPCGasCap = big.NewInt(0)
	}
	if sdTimeout := viper.GetString("ethereum.stateDiffTimeout"); sdTimeout != "" {
		var err error
		if c.StateDiffTimeout, err = time.ParseDuration(sdTimeout); err != nil {
			return nil, err
		}
	} else {
		c.StateDiffTimeout = ethServerShared.DefaultStateDiffTimeout
	}
	if c.StateDiffTimeout < 0 {
		return nil, errors.New("ethereum.stateDiffTimeout < 0")
	}
	chainConfigPath := viper.GetString("ethereum.chainConfig")
	if chainConfigPath != "" {
		c.ChainConfig, err = utils.LoadConfig(chainConfigPath)
	} else {
		c.ChainConfig, err = utils.ChainConfig(nodeInfo.ChainID)
	}

	c.loadGroupCacheConfig()

	c.loadValidatorConfig()

	return c, err
}

func overrideDBConnConfig(con *postgres.Config) {
	viper.BindEnv("database.server.maxIdle", SERVER_MAX_IDLE_CONNECTIONS)
	viper.BindEnv("database.server.maxOpen", SERVER_MAX_OPEN_CONNECTIONS)
	viper.BindEnv("database.server.maxLifetime", SERVER_MAX_CONN_LIFETIME)
	con.MaxIdle = viper.GetInt("database.server.maxIdle")
	con.MaxConns = viper.GetInt("database.server.maxOpen")
	con.MaxConnLifetime = time.Duration(viper.GetInt("database.server.maxLifetime"))
}

func (c *Config) dbInit() {
	viper.BindEnv("database.name", DATABASE_NAME)
	viper.BindEnv("database.hostname", DATABASE_HOSTNAME)
	viper.BindEnv("database.port", DATABASE_PORT)
	viper.BindEnv("database.user", DATABASE_USER)
	viper.BindEnv("database.password", DATABASE_PASSWORD)
	viper.BindEnv("database.maxIdle", DATABASE_MAX_IDLE_CONNECTIONS)
	viper.BindEnv("database.maxOpen", DATABASE_MAX_OPEN_CONNECTIONS)
	viper.BindEnv("database.maxLifetime", DATABASE_MAX_CONN_LIFETIME)

	c.DBConfig.DatabaseName = viper.GetString("database.name")
	c.DBConfig.Hostname = viper.GetString("database.hostname")
	c.DBConfig.Port = viper.GetInt("database.port")
	c.DBConfig.Username = viper.GetString("database.user")
	c.DBConfig.Password = viper.GetString("database.password")
	c.DBConfig.MaxIdle = viper.GetInt("database.maxIdle")
	c.DBConfig.MaxConns = viper.GetInt("database.maxOpen")
	c.DBConfig.MaxConnLifetime = time.Duration(viper.GetInt("database.maxLifetime"))
}

func (c *Config) loadGroupCacheConfig() {
	viper.BindEnv("groupcache.pool.enabled", ethServerShared.GcachePoolEnabled)
	viper.BindEnv("groupcache.pool.httpEndpoint", ethServerShared.GcachePoolHttpPath)
	viper.BindEnv("groupcache.pool.peerHttpEndpoints", ethServerShared.GcachePoolHttpPeers)
	viper.BindEnv("groupcache.statedb.cacheSizeInMB", ethServerShared.GcacheStatedbCacheSize)
	viper.BindEnv("groupcache.statedb.cacheExpiryInMins", ethServerShared.GcacheStatedbCacheExpiry)
	viper.BindEnv("groupcache.statedb.logStatsIntervalInSecs", ethServerShared.GcacheStatedbLogStatsInterval)

	gcc := ethServerShared.GroupCacheConfig{}
	gcc.Pool.Enabled = viper.GetBool("groupcache.pool.enabled")
	if gcc.Pool.Enabled {
		gcc.Pool.HttpEndpoint = viper.GetString("groupcache.pool.httpEndpoint")
		gcc.Pool.PeerHttpEndpoints = viper.GetStringSlice("groupcache.pool.peerHttpEndpoints")
	}

	// Irrespective of whether the pool is enabled, we always use the hot/local cache.
	gcc.StateDB.CacheSizeInMB = viper.GetInt("groupcache.statedb.cacheSizeInMB")
	gcc.StateDB.CacheExpiryInMins = viper.GetInt("groupcache.statedb.cacheExpiryInMins")
	gcc.StateDB.LogStatsIntervalInSecs = viper.GetInt("groupcache.statedb.logStatsIntervalInSecs")

	c.GroupCache = &gcc
}

func (c *Config) loadValidatorConfig() {
	viper.BindEnv("validator.enabled", VALIDATOR_ENABLED)
	viper.BindEnv("validator.everyNthBlock", VALIDATOR_EVERY_NTH_BLOCK)

	c.StateValidationEnabled = viper.GetBool("validator.enabled")
	c.StateValidationEveryNthBlock = viper.GetUint64("validator.everyNthBlock")
}

// GetEthNodeAndClient returns eth node info and client from path url
func getEthNodeAndClient(path string) (node.Info, *rpc.Client, error) {
	viper.BindEnv("ethereum.nodeID", ETH_NODE_ID)
	viper.BindEnv("ethereum.clientName", ETH_CLIENT_NAME)
	viper.BindEnv("ethereum.genesisBlock", ETH_GENESIS_BLOCK)
	viper.BindEnv("ethereum.networkID", ETH_NETWORK_ID)
	viper.BindEnv("ethereum.chainID", ETH_CHAIN_ID)

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
