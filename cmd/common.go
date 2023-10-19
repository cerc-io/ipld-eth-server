// Copyright © 2021 Vulcanize, Inc
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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addDatabaseFlags(command *cobra.Command) {
	// database flags
	command.PersistentFlags().String("database-name", "vulcanize_public", "database name")
	command.PersistentFlags().Int("database-port", 5432, "database port")
	command.PersistentFlags().String("database-hostname", "localhost", "database hostname")
	command.PersistentFlags().String("database-user", "", "database user")
	command.PersistentFlags().String("database-password", "", "database password")

	// database flag bindings
	viper.BindPFlag("database.name", command.PersistentFlags().Lookup("database-name"))
	viper.BindPFlag("database.port", command.PersistentFlags().Lookup("database-port"))
	viper.BindPFlag("database.hostname", command.PersistentFlags().Lookup("database-hostname"))
	viper.BindPFlag("database.user", command.PersistentFlags().Lookup("database-user"))
	viper.BindPFlag("database.password", command.PersistentFlags().Lookup("database-password"))
}

func addNitroFlags(command *cobra.Command) {
	// nitro flags
	command.PersistentFlags().Bool("nitro-run-node-in-process", false, "nitro run node in process")
	command.PersistentFlags().String("nitro-rpc-query-rates-file", "", "nitro rpcQueryRatesFile")

	command.PersistentFlags().String("nitro-pk", "", "nitro pk")
	command.PersistentFlags().String("nitro-chain-pk", "", "nitro chainPk")
	command.PersistentFlags().String("nitro-chain-url", "ws://127.0.0.1:8545", "nitro chainUrl")
	command.PersistentFlags().String("nitro-na-address", "", "nitro naAddress")
	command.PersistentFlags().String("nitro-vpa-address", "", "nitro vpaAddress")
	command.PersistentFlags().String("nitro-ca-address", "", "nitro caAddress")
	command.PersistentFlags().Bool("nitro-use-durable-store", false, "nitro useDurableStore")
	command.PersistentFlags().String("nitro-durable-store-folder", "", "nitro durableStoreFolder")
	command.PersistentFlags().Int("nitro-msg-port", 3005, "nitro msgPort")
	command.PersistentFlags().Int("nitro-rpc-port", 4005, "nitro rpcPort")
	command.PersistentFlags().Int("nitro-ws-msg-port", 5005, "nitro wsMsgPort")
	command.PersistentFlags().Uint("nitro-chain-start-block", 0, "nitro chainStartBlock")
	command.PersistentFlags().String("nitro-tls-cert-filepath", "", "nitro tlsCertFilepath")
	command.PersistentFlags().String("nitro-tls-key-filepath", "", "nitro tlsKeyFilepath")

	command.PersistentFlags().String("nitro-endpoint", "", "nitro endpoint")
	command.PersistentFlags().Bool("nitro-is-secure", false, "nitro isSecure")

	// nitro flag bindings
	viper.BindPFlag("nitro.runNodeInProcess", command.PersistentFlags().Lookup("nitro-run-node-in-process"))
	viper.BindPFlag("nitro.rpcQueryRatesFile", command.PersistentFlags().Lookup("nitro-rpc-query-rates-file"))

	viper.BindPFlag("nitro.inProcesssNode.pk", command.PersistentFlags().Lookup("nitro-pk"))
	viper.BindPFlag("nitro.inProcesssNode.chainPk", command.PersistentFlags().Lookup("nitro-chain-pk"))
	viper.BindPFlag("nitro.inProcesssNode.chainUrl", command.PersistentFlags().Lookup("nitro-chain-url"))
	viper.BindPFlag("nitro.inProcesssNode.naAddress", command.PersistentFlags().Lookup("nitro-na-address"))
	viper.BindPFlag("nitro.inProcesssNode.vpaAddress", command.PersistentFlags().Lookup("nitro-vpa-address"))
	viper.BindPFlag("nitro.inProcesssNode.caAddress", command.PersistentFlags().Lookup("nitro-ca-address"))
	viper.BindPFlag("nitro.inProcesssNode.useDurableStore", command.PersistentFlags().Lookup("nitro-use-durable-store"))
	viper.BindPFlag("nitro.inProcesssNode.durableStoreFolder", command.PersistentFlags().Lookup("nitro-durable-store"))
	viper.BindPFlag("nitro.inProcesssNode.msgPort", command.PersistentFlags().Lookup("nitro-msg-port"))
	viper.BindPFlag("nitro.inProcesssNode.rpcPort", command.PersistentFlags().Lookup("nitro-rpc-port"))
	viper.BindPFlag("nitro.inProcesssNode.wsMsgPort", command.PersistentFlags().Lookup("nitro-ws-msg-port"))
	viper.BindPFlag("nitro.inProcesssNode.chainStartBlock", command.PersistentFlags().Lookup("nitro-chain-start-block"))
	viper.BindPFlag("nitro.inProcesssNode.tlsCertFilepath", command.PersistentFlags().Lookup("nitro-tls-cert-filepath"))
	viper.BindPFlag("nitro.inProcesssNode.tlsKeyFilepath", command.PersistentFlags().Lookup("nitro-tls-key-filepath"))

	viper.BindPFlag("nitro.remoteNode.nitroEndpoint", command.PersistentFlags().Lookup("nitro-endpoint"))
	viper.BindPFlag("nitro.remoteNode.isSecure", command.PersistentFlags().Lookup("nitro-is-secure"))
}
