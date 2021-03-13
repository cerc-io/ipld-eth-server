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
	"os"
	"os/signal"
	"sync"

	"github.com/vulcanize/ipld-eth-server/pkg/graphql"

	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulcanize/ipld-eth-indexer/pkg/eth"

	srpc "github.com/vulcanize/ipld-eth-server/pkg/rpc"
	s "github.com/vulcanize/ipld-eth-server/pkg/serve"
	v "github.com/vulcanize/ipld-eth-server/version"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve chain data from PG-IPFS",
	Long: `This command configures a VulcanizeDB ipld-eth-server.

`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		serve()
	},
}

func serve() {
	logWithCommand.Infof("running ipld-eth-server version: %s", v.VersionWithMeta)

	var forwardPayloadChan chan eth.ConvertedPayload
	wg := new(sync.WaitGroup)
	logWithCommand.Debug("loading server configuration variables")
	serverConfig, err := s.NewConfig()
	if err != nil {
		logWithCommand.Fatal(err)
	}
	logWithCommand.Infof("server config: %+v", serverConfig)
	logWithCommand.Debug("initializing new server service")
	server, err := s.NewServer(serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	logWithCommand.Info("starting up server servers")
	forwardPayloadChan = make(chan eth.ConvertedPayload, s.PayloadChanBufferSize)
	server.Serve(wg, forwardPayloadChan)
	if err := startServers(server, serverConfig); err != nil {
		logWithCommand.Fatal(err)
	}
	graphQL, err := startGraphQL(server)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	shutdown := make(chan os.Signal)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
	if graphQL != nil {
		graphQL.Stop()
	}
	server.Stop()
	wg.Wait()
}

func startServers(server s.Server, settings *s.Config) error {
	logWithCommand.Info("starting up IPC server")
	_, _, err := srpc.StartIPCEndpoint(settings.IPCEndpoint, server.APIs())
	if err != nil {
		return err
	}
	logWithCommand.Info("starting up WS server")
	_, _, err = srpc.StartWSEndpoint(settings.WSEndpoint, server.APIs(), []string{"vdb"}, nil, true)
	if err != nil {
		return err
	}
	logWithCommand.Info("starting up HTTP server")
	_, err = srpc.StartHTTPEndpoint(settings.HTTPEndpoint, server.APIs(), []string{"eth"}, nil, []string{"*"}, rpc.HTTPTimeouts{})
	return err
}

func startGraphQL(server s.Server) (graphQLServer *graphql.Service, err error) {
	viper.BindEnv("server.graphql", "SERVER_GRAPHQL")
	if viper.GetBool("server.graphql") {
		logWithCommand.Info("starting up GraphQL server")
		viper.BindEnv("server.graphqlEndpoint", "SERVER_GRAPHQL_ENDPOINT")
		endPoint := viper.GetString("server.graphqlEndpoint")
		if endPoint != "" {
			graphQLServer, err = graphql.New(server.Backend(), endPoint, nil, []string{"*"}, rpc.HTTPTimeouts{})
			if err != nil {
				return
			}
			err = graphQLServer.Start(nil)
		}
	}
	return
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// flags for all config variables
	serveCmd.PersistentFlags().Bool("server-graphql", false, "turn on the graphql server")
	serveCmd.PersistentFlags().String("server-graphql-endpoint", "", "endpoint url for graphql server")
	serveCmd.PersistentFlags().String("server-ws-path", "", "vdb server ws path")
	serveCmd.PersistentFlags().String("server-http-path", "", "vdb server http path")
	serveCmd.PersistentFlags().String("server-ipc-path", "", "vdb server ipc path")

	serveCmd.PersistentFlags().String("eth-http-path", "", "http url for ethereum node")
	serveCmd.PersistentFlags().String("eth-node-id", "", "eth node id")
	serveCmd.PersistentFlags().String("eth-client-name", "Geth", "eth client name")
	serveCmd.PersistentFlags().String("eth-genesis-block", "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "eth genesis block hash")
	serveCmd.PersistentFlags().String("eth-network-id", "1", "eth network id")
	serveCmd.PersistentFlags().String("eth-chain-id", "1", "eth chain id")
	serveCmd.PersistentFlags().String("eth-default-sender", "", "default sender address")
	serveCmd.PersistentFlags().String("eth-rpc-gas-cap", "", "rpc gas cap (for eth_Call execution)")
	serveCmd.PersistentFlags().String("eth-chain-config", "", "json chain config file location")
	serveCmd.PersistentFlags().Bool("eth-supports-state-diff", false, "whether or not the proxy ethereum client supports statediffing endpoints")

	// and their bindings
	viper.BindPFlag("server.graphql", serveCmd.PersistentFlags().Lookup("server-graphql"))
	viper.BindPFlag("server.graphqlEndpoint", serveCmd.PersistentFlags().Lookup("server-graphql-endpoint"))
	viper.BindPFlag("server.wsPath", serveCmd.PersistentFlags().Lookup("server-ws-path"))
	viper.BindPFlag("server.httpPath", serveCmd.PersistentFlags().Lookup("server-http-path"))
	viper.BindPFlag("server.ipcPath", serveCmd.PersistentFlags().Lookup("server-ipc-path"))

	viper.BindPFlag("ethereum.httpPath", serveCmd.PersistentFlags().Lookup("eth-http-path"))
	viper.BindPFlag("ethereum.nodeID", serveCmd.PersistentFlags().Lookup("eth-node-id"))
	viper.BindPFlag("ethereum.clientName", serveCmd.PersistentFlags().Lookup("eth-client-name"))
	viper.BindPFlag("ethereum.genesisBlock", serveCmd.PersistentFlags().Lookup("eth-genesis-block"))
	viper.BindPFlag("ethereum.networkID", serveCmd.PersistentFlags().Lookup("eth-network-id"))
	viper.BindPFlag("ethereum.chainID", serveCmd.PersistentFlags().Lookup("eth-chain-id"))
	viper.BindPFlag("ethereum.defaultSender", serveCmd.PersistentFlags().Lookup("eth-default-sender"))
	viper.BindPFlag("ethereum.rpcGasCap", serveCmd.PersistentFlags().Lookup("eth-rpc-gas-cap"))
	viper.BindPFlag("ethereum.chainConfig", serveCmd.PersistentFlags().Lookup("eth-chain-config"))
	viper.BindPFlag("ethereum.supportsStateDiff", serveCmd.PersistentFlags().Lookup("eth-supports-state-diff"))
}
