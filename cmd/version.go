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
	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	"github.com/spf13/cobra"

	v "github.com/cerc-io/ipld-eth-server/v4/version"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the version of ipld-eth-server",
	Long: `Use this command to fetch the version of ipld-eth-server

Usage: ./ipld-eth-server version`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		logWithCommand.Infof("ipld-eth-server version: %s", v.VersionWithMeta)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
