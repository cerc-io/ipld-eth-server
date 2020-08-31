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
	s "sync"

	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth"

	"github.com/vulcanize/ipld-eth-server/pkg/serve"
	v "github.com/vulcanize/ipld-eth-server/version"
)

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "serve chain data from PG-IPFS",
	Long: `This command configures a VulcanizeDB ipld-eth-server.

`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		watch()
	},
}

func watch() {
	logWithCommand.Infof("running ipld-eth-server version: %s", v.VersionWithMeta)

	var forwardPayloadChan chan eth.ConvertedPayload
	wg := new(s.WaitGroup)
	logWithCommand.Debug("loading watcher configuration variables")
	watcherConfig, err := serve.NewConfig()
	if err != nil {
		logWithCommand.Fatal(err)
	}
	logWithCommand.Infof("watcher config: %+v", watcherConfig)
	logWithCommand.Debug("initializing new watcher service")
	s, err := serve.NewServer(watcherConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	logWithCommand.Info("starting up watcher servers")
	forwardPayloadChan = make(chan eth.ConvertedPayload, serve.PayloadChanBufferSize)
	s.Serve(wg, forwardPayloadChan)
	if err := startServers(s, watcherConfig); err != nil {
		logWithCommand.Fatal(err)
	}


	shutdown := make(chan os.Signal)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
	s.Stop()
	wg.Wait()
}

func startServers(watcher serve.Server, settings *serve.Config) error {
	logWithCommand.Debug("starting up IPC server")
	_, _, err := rpc.StartIPCEndpoint(settings.IPCEndpoint, watcher.APIs())
	if err != nil {
		return err
	}
	logWithCommand.Debug("starting up WS server")
	_, _, err = rpc.StartWSEndpoint(settings.WSEndpoint, watcher.APIs(), []string{"vdb"}, nil, true)
	if err != nil {
		return err
	}
	logWithCommand.Debug("starting up HTTP server")
	_, _, err = rpc.StartHTTPEndpoint(settings.HTTPEndpoint, watcher.APIs(), []string{"eth"}, nil, nil, rpc.HTTPTimeouts{})
	return err
}

func init() {
	rootCmd.AddCommand(watchCmd)

	// flags for all config variables
	watchCmd.PersistentFlags().String("watcher-ws-path", "", "vdb server ws path")
	watchCmd.PersistentFlags().String("watcher-http-path", "", "vdb server http path")
	watchCmd.PersistentFlags().String("watcher-ipc-path", "", "vdb server ipc path")

	watchCmd.PersistentFlags().String("eth-ws-path", "", "ws url for ethereum node")
	watchCmd.PersistentFlags().String("eth-http-path", "", "http url for ethereum node")
	watchCmd.PersistentFlags().String("eth-node-id", "", "eth node id")
	watchCmd.PersistentFlags().String("eth-client-name", "", "eth client name")
	watchCmd.PersistentFlags().String("eth-genesis-block", "", "eth genesis block hash")
	watchCmd.PersistentFlags().String("eth-network-id", "", "eth network id")

	// and their bindings
	viper.BindPFlag("watcher.wsPath", watchCmd.PersistentFlags().Lookup("watcher-ws-path"))
	viper.BindPFlag("watcher.httpPath", watchCmd.PersistentFlags().Lookup("watcher-http-path"))
	viper.BindPFlag("watcher.ipcPath", watchCmd.PersistentFlags().Lookup("watcher-ipc-path"))

	viper.BindPFlag("ethereum.wsPath", watchCmd.PersistentFlags().Lookup("eth-ws-path"))
	viper.BindPFlag("ethereum.httpPath", watchCmd.PersistentFlags().Lookup("eth-http-path"))
	viper.BindPFlag("ethereum.nodeID", watchCmd.PersistentFlags().Lookup("eth-node-id"))
	viper.BindPFlag("ethereum.clientName", watchCmd.PersistentFlags().Lookup("eth-client-name"))
	viper.BindPFlag("ethereum.genesisBlock", watchCmd.PersistentFlags().Lookup("eth-genesis-block"))
	viper.BindPFlag("ethereum.networkID", watchCmd.PersistentFlags().Lookup("eth-network-id"))
}
