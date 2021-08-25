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
