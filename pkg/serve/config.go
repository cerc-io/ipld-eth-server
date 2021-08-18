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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff/indexer/postgres"
	"github.com/spf13/viper"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	ethServerShared "github.com/vulcanize/ipld-eth-server/pkg/shared"
)

// Env variables
const (
	serverWsPath   = "SERVER_WS_PATH"
	serverIpcPath  = "SERVER_IPC_PATH"
	serverHTTPPath = "SERVER_HTTP_PATH"

	serverMaxIdleConnections = "SERVER_MAX_IDLE_CONNECTIONS"
	serverMaxOpenConnections = "SERVER_MAX_OPEN_CONNECTIONS"
	serverMaxConnLifetime    = "SERVER_MAX_CONN_LIFETIME"

	ethDefaultSenderAddr = "ETH_DEFAULT_SENDER_ADDR"
	ethRPCGasCap         = "ETH_RPC_GAS_CAP"
	ethChainConfig       = "ETH_CHAIN_CONFIG"
	ethSupportsStatediff = "ETH_SUPPORTS_STATEDIFF"
)

// Config struct
type Config struct {
	DB       *postgres.DB
	DBConfig postgres.ConnectionConfig
	DBParams postgres.ConnectionParams

	WSEnabled  bool
	WSEndpoint string

	HTTPEnabled  bool
	HTTPEndpoint string

	IPCEnabled  bool
	IPCEndpoint string

	EthGraphqlEnabled  bool
	EthGraphqlEndpoint string

	IpldGraphqlEnabled          bool
	IpldGraphqlEndpoint         string
	IpldPostgraphileEndpoint    string
	TracingHttpEndpoint         string
	TracingPostgraphileEndpoint string

	ChainConfig      *params.ChainConfig
	DefaultSender    *common.Address
	RPCGasCap        *big.Int
	EthHttpEndpoint  string
	Client           *rpc.Client
	SupportStateDiff bool

	// Cache configuration.
	GroupCache *ethServerShared.GroupCacheConfig
}

// NewConfig is used to initialize a watcher config from a .toml file
// Separate chain watcher instances need to be ran with separate ipfs path in order to avoid lock contention on the ipfs repository lockfile
func NewConfig() (*Config, error) {
	c := new(Config)

	viper.BindEnv("ethereum.httpPath", ethHTTPPath)
	viper.BindEnv("ethereum.defaultSender", ethDefaultSenderAddr)
	viper.BindEnv("ethereum.rpcGasCap", ethRPCGasCap)
	viper.BindEnv("ethereum.chainConfig", ethChainConfig)
	viper.BindEnv("ethereum.supportsStateDiff", ethSupportsStatediff)

	c.dbInit()
	ethHTTP := viper.GetString("ethereum.httpPath")
	ethHTTPEndpoint := fmt.Sprintf("http://%s", ethHTTP)
	nodeInfo, cli, err := getEthNodeAndClient(ethHTTPEndpoint)
	if err != nil {
		return nil, err
	}
	c.Client = cli
	c.SupportStateDiff = viper.GetBool("ethereum.supportsStateDiff")
	c.EthHttpEndpoint = ethHTTPEndpoint

	// websocket server
	wsEnabled := viper.GetBool("eth.server.ws")
	if wsEnabled {
		wsPath := viper.GetString("eth.server.wsPath")
		if wsPath == "" {
			wsPath = "127.0.0.1:8080"
		}
		c.WSEndpoint = wsPath
	}
	c.WSEnabled = wsEnabled

	// ipc server
	ipcEnabled := viper.GetBool("eth.server.ipc")
	if ipcEnabled {
		ipcPath := viper.GetString("eth.server.ipcPath")
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
	httpEnabled := viper.GetBool("eth.server.http")
	if httpEnabled {
		httpPath := viper.GetString("eth.server.httpPath")
		if httpPath == "" {
			httpPath = "127.0.0.1:8081"
		}
		c.HTTPEndpoint = httpPath
	}
	c.HTTPEnabled = httpEnabled

	// eth graphql endpoint
	ethGraphqlEnabled := viper.GetBool("eth.server.graphql")
	if ethGraphqlEnabled {
		ethGraphqlPath := viper.GetString("eth.server.graphqlPath")
		if ethGraphqlPath == "" {
			ethGraphqlPath = "127.0.0.1:8082"
		}
		c.EthGraphqlEndpoint = ethGraphqlPath
	}
	c.EthGraphqlEnabled = ethGraphqlEnabled

	// ipld graphql endpoint
	ipldGraphqlEnabled := viper.GetBool("ipld.server.graphql")
	if ipldGraphqlEnabled {
		ipldGraphqlPath := viper.GetString("ipld.server.graphqlPath")
		if ipldGraphqlPath == "" {
			ipldGraphqlPath = "127.0.0.1:8083"
		}
		c.IpldGraphqlEndpoint = ipldGraphqlPath

		ipldPostgraphilePath := viper.GetString("ipld.postgraphilePath")
		if ipldPostgraphilePath == "" {
			return nil, errors.New("ipld-postgraphile-path parameter is empty")
		}
		c.IpldPostgraphileEndpoint = ipldPostgraphilePath

		tracingHttpEndpoint := viper.GetString("tracing.httpPath")
		tracingPostgraphilePath := viper.GetString("tracing.postgraphilePath")

		// these two parameters either can be both empty or both set
		if (tracingHttpEndpoint == "" && tracingPostgraphilePath != "") || (tracingHttpEndpoint != "" && tracingPostgraphilePath == "") {
			return nil, errors.New("tracing.httpPath and tracing.postgraphilePath parameters either can be both empty or both set")
		}

		c.TracingHttpEndpoint = tracingHttpEndpoint
		c.TracingPostgraphileEndpoint = tracingPostgraphilePath
	}
	c.IpldGraphqlEnabled = ipldGraphqlEnabled

	overrideDBConnConfig(&c.DBConfig)
	serveDB, err := postgres.NewDB(postgres.DbConnectionString(c.DBParams), c.DBConfig, nodeInfo)
	if err != nil {
		return nil, err
	}

	prom.RegisterDBCollector(c.DBParams.Name, serveDB.DB)
	c.DB = serveDB

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

	c.loadGroupCacheConfig()

	return c, err
}

func overrideDBConnConfig(con *postgres.ConnectionConfig) {
	viper.BindEnv("database.server.maxIdle", serverMaxIdleConnections)
	viper.BindEnv("database.server.maxOpen", serverMaxOpenConnections)
	viper.BindEnv("database.server.maxLifetime", serverMaxConnLifetime)
	con.MaxIdle = viper.GetInt("database.server.maxIdle")
	con.MaxOpen = viper.GetInt("database.server.maxOpen")
	con.MaxLifetime = viper.GetInt("database.server.maxLifetime")
}

func (d *Config) dbInit() {
	viper.BindEnv("database.name", databaseName)
	viper.BindEnv("database.hostname", databaseHostname)
	viper.BindEnv("database.port", databasePort)
	viper.BindEnv("database.user", databaseUser)
	viper.BindEnv("database.password", databasePassword)
	viper.BindEnv("database.maxIdle", databaseMaxIdleConnections)
	viper.BindEnv("database.maxOpen", databaseMaxOpenConnections)
	viper.BindEnv("database.maxLifetime", databaseMaxOpenConnLifetime)

	d.DBParams.Name = viper.GetString("database.name")
	d.DBParams.Hostname = viper.GetString("database.hostname")
	d.DBParams.Port = viper.GetInt("database.port")
	d.DBParams.User = viper.GetString("database.user")
	d.DBParams.Password = viper.GetString("database.password")
	d.DBConfig.MaxIdle = viper.GetInt("database.maxIdle")
	d.DBConfig.MaxOpen = viper.GetInt("database.maxOpen")
	d.DBConfig.MaxLifetime = viper.GetInt("database.maxLifetime")
}

func (c *Config) loadGroupCacheConfig() {
	viper.BindEnv("groupcache.pool.enabled", ethServerShared.GCACHE_POOL_ENABLED)
	viper.BindEnv("groupcache.pool.httpEndpoint", ethServerShared.GCACHE_POOL_HTTP_PATH)
	viper.BindEnv("groupcache.pool.peerHttpEndpoints", ethServerShared.GCACHE_POOL_HTTP_PEERS)
	viper.BindEnv("groupcache.statedb.cacheSizeInMB", ethServerShared.GCACHE_STATEDB_CACHE_SIZE)
	viper.BindEnv("groupcache.statedb.cacheExpiryInMins", ethServerShared.GCACHE_STATEDB_CACHE_EXPIRY)
	viper.BindEnv("groupcache.statedb.logStatsIntervalInSecs", ethServerShared.GCACHE_STATEDB_LOG_STATS_INTERVAL)

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
