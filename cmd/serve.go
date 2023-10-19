// Copyright © 2020 Vulcanize, Inc
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/mailgun/groupcache/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/statechannels/go-nitro/node/engine"
	"github.com/statechannels/go-nitro/node/engine/chainservice"
	nitroStore "github.com/statechannels/go-nitro/node/engine/store"
	"github.com/statechannels/go-nitro/paymentsmanager"
	"github.com/statechannels/go-nitro/rpc/transport"
	"golang.org/x/exp/slog"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/graphql"
	srpc "github.com/cerc-io/ipld-eth-server/v5/pkg/rpc"
	s "github.com/cerc-io/ipld-eth-server/v5/pkg/serve"
	v "github.com/cerc-io/ipld-eth-server/v5/version"
	nitroNode "github.com/statechannels/go-nitro/node"
	nitrop2pms "github.com/statechannels/go-nitro/node/engine/messageservice/p2p-message-service"
	nitroRpc "github.com/statechannels/go-nitro/rpc"
	nitroHttpTransport "github.com/statechannels/go-nitro/rpc/transport/http"
)

var ErrNoRpcEndpoints = errors.New("no rpc endpoints is available")

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve chain data from PG-IPFS",
	Long:  `This command configures a VulcanizeDB ipld-eth-server.`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		serve()
	},
}

func serve() {
	logWithCommand.Infof("ipld-eth-server version: %s", v.VersionWithMeta)

	wg := new(sync.WaitGroup)
	defer wg.Wait()

	serverConfig, err := s.NewConfig()
	if err != nil {
		logWithCommand.Fatal(err)
	}
	logWithCommand.Debugf("server config: %+v", serverConfig)
	server, err := s.NewServer(serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}
	if serverConfig.ForwardEthCalls {
		logWithCommand.Info("Fowarding eth_call")
	}
	if serverConfig.ForwardGetStorageAt {
		logWithCommand.Info("Fowarding eth_getStorageAt")
	}
	if serverConfig.ProxyOnError {
		logWithCommand.Info("Proxy on error is enabled")
	}

	server.Serve(wg)

	var voucherValidator paymentsmanager.VoucherValidator

	nitroConfig := serverConfig.Nitro
	if nitroConfig.RunNodeInProcess {
		log.Info("Running an in-process Nitro node")

		pm, nitroRpcServer := initNitroInProcess(wg, nitroConfig)
		defer pm.Stop()
		defer nitroRpcServer.Close()

		voucherValidator = paymentsmanager.InProcessVoucherValidator{PaymentsManager: *pm}
	} else {
		log.Info("Connecting to a remote Nitro node")

		isSecure := nitroConfig.RemoteNode.IsSecure
		nitroRpcClient, err := nitroRpc.NewHttpRpcClient(nitroConfig.RemoteNode.NitroEndpoint, isSecure)
		if err != nil {
			logWithCommand.Fatal(err)
		}
		defer nitroRpcClient.Close()

		voucherValidator = nitroRpc.RemoteVoucherValidator{Client: nitroRpcClient}
	}

	queryRates, err := readRpcQueryRates(nitroConfig.RpcQueryRatesFile)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	paymentMiddleware := func(next http.Handler) http.Handler {
		return paymentsmanager.HTTPMiddleware(next, voucherValidator, queryRates)
	}

	if err := startServers(server, serverConfig, [](func(next http.Handler) http.Handler){paymentMiddleware}); err != nil {
		logWithCommand.Fatal(err)
	}
	graphQL, err := startEthGraphQL(server, serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	err = startGroupCacheService(serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	if serverConfig.StateValidationEnabled {
		go startStateTrieValidator(serverConfig, server)
		logWithCommand.Info("state validator enabled")
	} else {
		logWithCommand.Debug("state validator disabled")
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
	if graphQL != nil {
		graphQL.Stop()
	}
	server.Stop()
}

func startServers(server s.Server, settings *s.Config, httpMiddlewares [](func(next http.Handler) http.Handler)) error {
	if settings.IPCEnabled {
		logWithCommand.Debug("starting up IPC server")
		_, _, err := srpc.StartIPCEndpoint(settings.IPCEndpoint, server.APIs())
		if err != nil {
			return err
		}
	} else {
		logWithCommand.Debug("IPC server is disabled")
	}

	if settings.WSEnabled {
		logWithCommand.Debug("starting up WS server")
		_, _, err := srpc.StartWSEndpoint(settings.WSEndpoint, server.APIs(), []string{"vdb", "net"}, nil)
		if err != nil {
			return err
		}
	} else {
		logWithCommand.Debug("WS server is disabled")
	}

	if settings.HTTPEnabled {
		logWithCommand.Debug("starting up HTTP server")
		_, err := srpc.StartHTTPEndpoint(settings.HTTPEndpoint, server.APIs(), []string{"vdb", "eth", "debug", "net"}, nil, []string{"*"}, rpc.HTTPTimeouts{}, httpMiddlewares)
		if err != nil {
			return err
		}
	} else {
		logWithCommand.Debug("HTTP server is disabled")
	}

	return nil
}

func startEthGraphQL(server s.Server, settings *s.Config) (graphQLServer *graphql.Service, err error) {
	if settings.EthGraphqlEnabled {
		logWithCommand.Debug("starting up ETH GraphQL server")
		endPoint := settings.EthGraphqlEndpoint
		if endPoint != "" {
			graphQLServer, err = graphql.New(server.Backend(), endPoint, nil, []string{"*"}, rpc.HTTPTimeouts{})
			if err != nil {
				return
			}
			err = graphQLServer.Start(nil)
		}
	} else {
		logWithCommand.Debug("ETH GraphQL server is disabled")
	}

	return
}

func startGroupCacheService(settings *s.Config) error {
	gcc := settings.GroupCache

	if gcc.Pool.Enabled {
		logWithCommand.Debug("starting up groupcache pool HTTTP server")

		pool := groupcache.NewHTTPPoolOpts(gcc.Pool.HttpEndpoint, &groupcache.HTTPPoolOptions{})
		pool.Set(gcc.Pool.PeerHttpEndpoints...)

		httpURL, err := url.Parse(gcc.Pool.HttpEndpoint)
		if err != nil {
			return err
		}

		server := http.Server{
			Addr:    httpURL.Host,
			Handler: pool,
		}

		// Start a HTTP server to listen for peer requests from the groupcache
		go server.ListenAndServe()

		logWithCommand.Infof("groupcache pool endpoint opened at %s", httpURL)
	} else {
		logWithCommand.Debug("Groupcache pool is disabled")
	}

	return nil
}

func startStateTrieValidator(config *s.Config, server s.Server) {
	validateEveryNthBlock := config.StateValidationEveryNthBlock

	var lastBlockNumber uint64
	backend := server.Backend()

	for {
		time.Sleep(5 * time.Second)

		block, err := backend.CurrentBlock()
		if err != nil {
			log.Error("Error fetching current block for state trie validator")
			continue
		}

		stateRoot := block.Root()
		blockNumber := block.NumberU64()
		blockHash := block.Hash()

		if validateEveryNthBlock <= 0 || // Used for static replicas where block number doesn't progress.
			(blockNumber > lastBlockNumber) && (blockNumber%validateEveryNthBlock == 0) {

			// The validate trie call will take a long time on mainnet, e.g. a few hours.
			if err = backend.ValidateTrie(stateRoot); err != nil {
				log.Fatalf("Error validating trie for block number %d hash %s state root %s",
					blockNumber,
					blockHash,
					stateRoot,
				)
			}

			log.Infof("Successfully validated trie for block number %d hash %s state root %s",
				blockNumber,
				blockHash,
				stateRoot,
			)

			if validateEveryNthBlock <= 0 {
				// Static replica, sleep a long-ish time (1/2 of cache expiry time) since we only need to keep the cache warm.
				time.Sleep((time.Minute * time.Duration(config.GroupCache.StateDB.CacheExpiryInMins)) / 2)
			}

			lastBlockNumber = blockNumber
		}
	}
}

func parseRpcAddresses(value string) ([]*rpc.Client, error) {
	rpcAddresses := strings.Split(value, ",")
	rpcClients := make([]*rpc.Client, 0, len(rpcAddresses))
	for _, address := range rpcAddresses {
		rpcClient, err := rpc.Dial(address)
		if err != nil {
			logWithCommand.Errorf("couldn't connect to %s. Error: %s", address, err)
			continue
		}

		rpcClients = append(rpcClients, rpcClient)
	}

	if len(rpcClients) == 0 {
		logWithCommand.Error(ErrNoRpcEndpoints)
		return nil, ErrNoRpcEndpoints
	}

	return rpcClients, nil
}

func init() {
	rootCmd.AddCommand(serveCmd)

	addDatabaseFlags(serveCmd)

	addNitroFlags(serveCmd)

	// flags for all config variables
	// eth graphql and json-rpc parameters
	serveCmd.PersistentFlags().Bool("server-graphql", false, "turn on the eth graphql server")
	serveCmd.PersistentFlags().String("server-graphql-path", "", "endpoint url for eth graphql server (host:port)")
	serveCmd.PersistentFlags().Bool("server-http", true, "turn on the eth http json-rpc server")
	serveCmd.PersistentFlags().String("server-http-path", "", "endpoint url for eth http json-rpc server (host:port)")
	serveCmd.PersistentFlags().Bool("server-ws", false, "turn on the eth websocket json-rpc server")
	serveCmd.PersistentFlags().String("server-ws-path", "", "endpoint url for eth websocket json-rpc server (host:port)")
	serveCmd.PersistentFlags().Bool("server-ipc", false, "turn on the eth ipc json-rpc server")
	serveCmd.PersistentFlags().String("server-ipc-path", "", "path for eth ipc json-rpc server")

	serveCmd.PersistentFlags().String("eth-http-path", "", "http url for ethereum node")
	serveCmd.PersistentFlags().String("eth-node-id", "", "eth node id")
	serveCmd.PersistentFlags().String("eth-client-name", "Geth", "eth client name")
	serveCmd.PersistentFlags().String("eth-genesis-block", "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "eth genesis block hash")
	serveCmd.PersistentFlags().String("eth-network-id", "1", "eth network id")
	serveCmd.PersistentFlags().String("eth-chain-id", "1", "eth chain id")
	serveCmd.PersistentFlags().String("eth-default-sender", "", "default sender address")
	serveCmd.PersistentFlags().String("eth-rpc-gas-cap", "", "rpc gas cap (for eth_Call execution)")
	serveCmd.PersistentFlags().String("eth-chain-config", "", "json chain config file location")
	serveCmd.PersistentFlags().Bool("eth-supports-state-diff", false, "whether the proxy ethereum client supports statediffing endpoints")
	serveCmd.PersistentFlags().Bool("eth-forward-eth-calls", false, "whether to immediately forward eth_calls to proxy client")
	serveCmd.PersistentFlags().Bool("eth-proxy-on-error", true, "whether to forward all failed calls to proxy client")

	// groupcache flags
	serveCmd.PersistentFlags().Bool("gcache-pool-enabled", false, "turn on the groupcache pool")
	serveCmd.PersistentFlags().String("gcache-pool-http-path", "", "http url for groupcache node")
	serveCmd.PersistentFlags().StringArray("gcache-pool-http-peers", []string{}, "http urls for groupcache peers")
	serveCmd.PersistentFlags().Int("gcache-statedb-cache-size", 16, "state DB cache size in MB")
	serveCmd.PersistentFlags().Int("gcache-statedb-cache-expiry", 60, "state DB cache expiry time in mins")
	serveCmd.PersistentFlags().Int("gcache-statedb-log-stats-interval", 60, "state DB cache stats log interval in secs")

	// state validator flags
	serveCmd.PersistentFlags().Bool("validator-enabled", false, "turn on the state validator")
	serveCmd.PersistentFlags().Uint("validator-every-nth-block", 1500, "only validate every Nth block")

	// and their bindings
	// eth graphql server
	viper.BindPFlag("server.graphql", serveCmd.PersistentFlags().Lookup("server-graphql"))
	viper.BindPFlag("server.graphqlPath", serveCmd.PersistentFlags().Lookup("server-graphql-path"))

	// eth http json-rpc server
	viper.BindPFlag("server.http", serveCmd.PersistentFlags().Lookup("server-http"))
	viper.BindPFlag("server.httpPath", serveCmd.PersistentFlags().Lookup("server-http-path"))

	// eth websocket json-rpc server
	viper.BindPFlag("server.ws", serveCmd.PersistentFlags().Lookup("server-ws"))
	viper.BindPFlag("server.wsPath", serveCmd.PersistentFlags().Lookup("server-ws-path"))

	// eth ipc json-rpc server
	viper.BindPFlag("server.ipc", serveCmd.PersistentFlags().Lookup("server-ipc"))
	viper.BindPFlag("server.ipcPath", serveCmd.PersistentFlags().Lookup("server-ipc-path"))

	viper.BindPFlag("ethereum.httpPath", serveCmd.PersistentFlags().Lookup("eth-http-path"))
	viper.BindPFlag("ethereum.nodeID", serveCmd.PersistentFlags().Lookup("eth-node-id"))
	viper.BindPFlag("ethereum.clientName", serveCmd.PersistentFlags().Lookup("eth-client-name"))
	viper.BindPFlag("ethereum.genesisBlock", serveCmd.PersistentFlags().Lookup("eth-genesis-block"))
	viper.BindPFlag("ethereum.networkID", serveCmd.PersistentFlags().Lookup("eth-network-id"))
	viper.BindPFlag("ethereum.chainID", serveCmd.PersistentFlags().Lookup("eth-chain-id"))
	viper.BindPFlag("ethereum.rpcGasCap", serveCmd.PersistentFlags().Lookup("eth-rpc-gas-cap"))
	viper.BindPFlag("ethereum.chainConfig", serveCmd.PersistentFlags().Lookup("eth-chain-config"))
	viper.BindPFlag("ethereum.supportsStateDiff", serveCmd.PersistentFlags().Lookup("eth-supports-state-diff"))
	viper.BindPFlag("ethereum.forwardEthCalls", serveCmd.PersistentFlags().Lookup("eth-forward-eth-calls"))
	viper.BindPFlag("ethereum.forwardGetStorageAt", serveCmd.PersistentFlags().Lookup("eth-forward-get-storage-at"))
	viper.BindPFlag("ethereum.proxyOnError", serveCmd.PersistentFlags().Lookup("eth-proxy-on-error"))
	viper.BindPFlag("ethereum.getLogsBlockLimit", serveCmd.PersistentFlags().Lookup("eth-getlogs-block-limit"))

	// groupcache flags
	viper.BindPFlag("groupcache.pool.enabled", serveCmd.PersistentFlags().Lookup("gcache-pool-enabled"))
	viper.BindPFlag("groupcache.pool.httpEndpoint", serveCmd.PersistentFlags().Lookup("gcache-pool-http-path"))
	viper.BindPFlag("groupcache.pool.peerHttpEndpoints", serveCmd.PersistentFlags().Lookup("gcache-pool-http-peers"))
	viper.BindPFlag("groupcache.statedb.cacheSizeInMB", serveCmd.PersistentFlags().Lookup("gcache-statedb-cache-size"))
	viper.BindPFlag("groupcache.statedb.cacheExpiryInMins", serveCmd.PersistentFlags().Lookup("gcache-statedb-cache-expiry"))
	viper.BindPFlag("groupcache.statedb.logStatsIntervalInSecs", serveCmd.PersistentFlags().Lookup("gcache-statedb-log-stats-interval"))

	// state validator flags
	viper.BindPFlag("validator.enabled", serveCmd.PersistentFlags().Lookup("validator-enabled"))
	viper.BindPFlag("validator.everyNthBlock", serveCmd.PersistentFlags().Lookup("validator-every-nth-block"))
}

// Initializes an in-process Nitro node, payments manager and a Nitro RPC server
func initNitroInProcess(wg *sync.WaitGroup, nitroConfig *s.NitroConfig) (*paymentsmanager.PaymentsManager, *nitroRpc.RpcServer) {
	nitroNode, err := initNitroNode(&nitroConfig.InProcessNode)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	pm, err := paymentsmanager.NewPaymentsManager(nitroNode)
	if err != nil {
		logWithCommand.Fatal(err)
	}
	pm.Start(wg)

	tlsCertFilepath := nitroConfig.InProcessNode.TlsCertFilepath
	tlsKeyFilepath := nitroConfig.InProcessNode.TlsKeyFilepath

	var cert *tls.Certificate
	if tlsCertFilepath != "" && tlsKeyFilepath != "" {
		*cert, err = tls.LoadX509KeyPair(tlsCertFilepath, tlsKeyFilepath)
		if err != nil {
			logWithCommand.Fatal(err)
		}
	}

	nitroRpcServer, err := initNitroRpcServer(nitroNode, pm, cert, nitroConfig.InProcessNode.RpcPort)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	return &pm, nitroRpcServer
}

// https://github.com/cerc-io/go-nitro/blob/release-v0.1.1-ts-port-0.1.7/internal/node/node.go#L17
func initNitroNode(config *s.InProcessNitroNodeConfig) (*nitroNode.Node, error) {
	pkString := config.Pk
	useDurableStore := config.UseDurableStore
	durableStoreFolder := config.DurableStoreFolder
	msgPort := config.MsgPort
	wsMsgPort := config.WsMsgPort
	chainUrl := config.ChainUrl
	chainStartBlock := config.ChainStartBlock
	chainPk := config.ChainPk
	naAddress := config.NaAddress
	vpaAddress := config.VpaAddress
	caAddress := config.CaAddress

	chainAuthToken := ""
	publicIp := "0.0.0.0"

	chainOpts := chainservice.ChainOpts{
		ChainUrl:        chainUrl,
		ChainStartBlock: chainStartBlock,
		ChainAuthToken:  chainAuthToken,
		ChainPk:         chainPk,
		NaAddress:       common.HexToAddress(naAddress),
		VpaAddress:      common.HexToAddress(vpaAddress),
		CaAddress:       common.HexToAddress(caAddress),
	}

	storeOpts := nitroStore.StoreOpts{
		PkBytes:            common.Hex2Bytes(pkString),
		UseDurableStore:    useDurableStore,
		DurableStoreFolder: durableStoreFolder,
	}

	bootPeers := []string{}
	messageOpts := nitrop2pms.MessageOpts{
		PkBytes:   common.Hex2Bytes(pkString),
		TcpPort:   msgPort,
		WsMsgPort: wsMsgPort,
		BootPeers: bootPeers,
		PublicIp:  publicIp,
	}

	ourStore, err := nitroStore.NewStore(storeOpts)
	if err != nil {
		return nil, err
	}

	log.Info("Initializing message service...", " tcp port=", msgPort, " web socket port=", wsMsgPort)
	messageService := nitrop2pms.NewMessageService(messageOpts)

	// Compare chainOpts.ChainStartBlock to lastBlockNum seen in store. The larger of the two
	// gets passed as an argument when creating NewEthChainService
	storeBlockNum, err := ourStore.GetLastBlockNumSeen()
	if err != nil {
		return nil, err
	}
	if storeBlockNum > chainOpts.ChainStartBlock {
		chainOpts.ChainStartBlock = storeBlockNum
	}

	log.Info("Initializing chain service...")
	ourChain, err := chainservice.NewEthChainService(chainOpts)
	if err != nil {
		return nil, err
	}

	node := nitroNode.New(
		messageService,
		ourChain,
		ourStore,
		&engine.PermissivePolicy{},
	)

	return &node, nil
}

func initNitroRpcServer(node *nitroNode.Node, pm paymentsmanager.PaymentsManager, cert *tls.Certificate, rpcPort int) (*nitroRpc.RpcServer, error) {
	var transport transport.Responder
	var err error

	slog.Info("Initializing Nitro HTTP RPC transport...")
	transport, err = nitroHttpTransport.NewHttpTransportAsServer(fmt.Sprint(rpcPort), cert)
	if err != nil {
		return nil, err
	}

	rpcServer, err := nitroRpc.NewRpcServer(node, pm, transport)
	if err != nil {
		return nil, err
	}

	slog.Info("Completed Nitro RPC server initialization")
	return rpcServer, nil
}

func readRpcQueryRates(filepath string) (map[string]*big.Int, error) {
	result := make(map[string]*big.Int)

	if filepath == "" {
		logWithCommand.Warn("RPC query rates file path not provided")
		return result, nil
	}

	jsonFile, err := os.Open(filepath)
	defer jsonFile.Close()

	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logWithCommand.Warn("RPC query rates file does not exist")
			return result, nil
		}
		return nil, err
	}

	decoder := json.NewDecoder(jsonFile)
	err = decoder.Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
