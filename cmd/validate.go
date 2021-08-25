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
	"time"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	validator "github.com/vulcanize/eth-ipfs-state-validator/pkg"
	ipfsethdb "github.com/vulcanize/ipfs-ethdb/postgres"
	s "github.com/vulcanize/ipld-eth-server/pkg/serve"
)

const GroupName = "statedb-validate"
const CacheExpiryInMins = 8 * 60 // 8 hours
const CacheSizeInMB = 16         // 16 MB

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "valdiate state",
	Long:  `This command validates the trie for the given state root`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		validate()
	},
}

func validate() {
	config, err := s.NewConfig()
	if err != nil {
		logWithCommand.Fatal(err)
	}

	stateRootStr := viper.GetString("stateRoot")
	if stateRootStr == "" {
		logWithCommand.Fatal("must provide a state root for state validation")
	}

	stateRoot := common.HexToHash(stateRootStr)
	cacheSize := viper.GetInt("cacheSize")

	ethDB := ipfsethdb.NewDatabase(config.DB.DB, ipfsethdb.CacheConfig{
		Name:           GroupName,
		Size:           cacheSize * 1024 * 1024,
		ExpiryDuration: time.Minute * time.Duration(CacheExpiryInMins),
	})

	validator := validator.NewValidator(nil, ethDB)
	if err = validator.ValidateTrie(stateRoot); err != nil {
		log.Fatalln("Error validating state root")
	}

	stats := ethDB.GetCacheStats()
	log.Debugf("groupcache stats %+v", stats)

	log.Infoln("Successfully validated state root")
}

func init() {
	rootCmd.AddCommand(validateCmd)

	addDatabaseFlags(validateCmd)

	validateCmd.PersistentFlags().String("state-root", "", "root of the state trie we wish to validate")
	viper.BindPFlag("stateRoot", validateCmd.PersistentFlags().Lookup("state-root"))

	validateCmd.PersistentFlags().Int("cache-size", CacheSizeInMB, "cache size in MB")
	viper.BindPFlag("cacheSize", validateCmd.PersistentFlags().Lookup("cache-size"))
}
