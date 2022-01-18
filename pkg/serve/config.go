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

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"
	ethServerShared "github.com/vulcanize/ipld-eth-server/pkg/shared"
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
	ETH_FORWARD_ETH_CALLS   = "ETH_FORWARD_ETH_CALLS"
	ETH_PROXY_ON_ERROR      = "ETH_PROXY_ON_ERROR"

	VALIDATOR_ENABLED         = "VALIDATOR_ENABLED"
	VALIDATOR_EVERY_NTH_BLOCK = "VALIDATOR_EVERY_NTH_BLOCK"

	GAP_FILLER_ENABLED  = "GAP_FILLER_ENABLED"
	GAP_FILLER_INTERVAL = "GAP_FILLER_INTERVAL"
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
	ForwardEthCalls  bool
	ProxyOnError     bool

	// Cache configuration.
	GroupCache *ethServerShared.GroupCacheConfig

	StateValidationEnabled       bool
	StateValidationEveryNthBlock uint64

	WatchedAddressGapFillerEnabled bool
	WatchedAddressGapFillInterval  int
}

// NewConfig is used to initialize a watcher config from a .toml file
// Separate chain watcher instances need to be ran with separate ipfs path in order to avoid lock contention on the ipfs repository lockfile
func NewConfig() (*Config, error) {
	c := new(Config)

	viper.BindEnv("ethereum.httpPath", ETH_HTTP_PATH)
	viper.BindEnv("ethereum.defaultSender", ETH_DEFAULT_SENDER_ADDR)
	viper.BindEnv("ethereum.rpcGasCap", ETH_RPC_GAS_CAP)
	viper.BindEnv("ethereum.chainConfig", ETH_CHAIN_CONFIG)
	viper.BindEnv("ethereum.supportsStateDiff", ETH_SUPPORTS_STATEDIFF)
	viper.BindEnv("ethereum.forwardEthCalls", ETH_FORWARD_ETH_CALLS)
	viper.BindEnv("ethereum.proxyOnError", ETH_PROXY_ON_ERROR)

	c.dbInit()
	ethHTTP := viper.GetString("ethereum.httpPath")
	ethHTTPEndpoint := fmt.Sprintf("http://%s", ethHTTP)
	nodeInfo, cli, err := getEthNodeAndClient(ethHTTPEndpoint)
	if err != nil {
		return nil, err
	}
	c.Client = cli
	c.SupportStateDiff = viper.GetBool("ethereum.supportsStateDiff")
	c.ForwardEthCalls = viper.GetBool("ethereum.forwardEthCalls")
	c.ProxyOnError = viper.GetBool("ethereum.proxyOnError")
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

	c.loadValidatorConfig()

	c.loadGapFillerConfig()

	return c, err
}

func overrideDBConnConfig(con *postgres.ConnectionConfig) {
	viper.BindEnv("database.server.maxIdle", SERVER_MAX_IDLE_CONNECTIONS)
	viper.BindEnv("database.server.maxOpen", SERVER_MAX_OPEN_CONNECTIONS)
	viper.BindEnv("database.server.maxLifetime", SERVER_MAX_CONN_LIFETIME)
	con.MaxIdle = viper.GetInt("database.server.maxIdle")
	con.MaxOpen = viper.GetInt("database.server.maxOpen")
	con.MaxLifetime = viper.GetInt("database.server.maxLifetime")
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

	c.DBParams.Name = viper.GetString("database.name")
	c.DBParams.Hostname = viper.GetString("database.hostname")
	c.DBParams.Port = viper.GetInt("database.port")
	c.DBParams.User = viper.GetString("database.user")
	c.DBParams.Password = viper.GetString("database.password")
	c.DBConfig.MaxIdle = viper.GetInt("database.maxIdle")
	c.DBConfig.MaxOpen = viper.GetInt("database.maxOpen")
	c.DBConfig.MaxLifetime = viper.GetInt("database.maxLifetime")
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

func (c *Config) loadGapFillerConfig() {
	viper.BindEnv("gapfiller.enabled", GAP_FILLER_ENABLED)
	viper.BindEnv("gapfiller.interval", GAP_FILLER_INTERVAL)

	c.WatchedAddressGapFillerEnabled = viper.GetBool("gapfiller.enabled")
	c.WatchedAddressGapFillInterval = viper.GetInt("gapfiller.interval")
}
