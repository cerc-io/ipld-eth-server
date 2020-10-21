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

package cmd

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"
)

var (
	cfgFile        string
	subCommand     string
	logWithCommand log.Entry
)

var rootCmd = &cobra.Command{
	Use:              "ipld-eth-server",
	PersistentPreRun: initFuncs,
}

func Execute() {
	log.Info("----- Starting IPFS blockchain watcher -----")
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func initFuncs(cmd *cobra.Command, args []string) {
	logfile := viper.GetString("logfile")
	if logfile != "" {
		file, err := os.OpenFile(logfile,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.Infof("Directing output to %s", logfile)
			log.SetOutput(file)
		} else {
			log.SetOutput(os.Stdout)
			log.Info("Failed to log to file, using default stdout")
		}
	} else {
		log.SetOutput(os.Stdout)
	}
	if err := logLevel(); err != nil {
		log.Fatal("Could not set log level: ", err)
	}

	if viper.GetBool("metrics") {
		prom.Init()
	}

	if viper.GetBool("http") {
		addr := fmt.Sprintf(
			"%s:%s",
			viper.GetString("http.addr"),
			viper.GetString("http.port"),
		)
		prom.Serve(addr)
	}
}

func logLevel() error {
	viper.BindEnv("log.level", "LOGRUS_LEVEL")
	lvl, err := log.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		return err
	}
	log.SetLevel(lvl)
	if lvl > log.InfoLevel {
		log.SetReportCaller(true)
	}
	log.Info("Log level set to ", lvl.String())
	return nil
}

func init() {
	cobra.OnInitialize(initConfig)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file location")
	rootCmd.PersistentFlags().String("logfile", "", "file path for logging")
	rootCmd.PersistentFlags().String("database-name", "vulcanize_public", "database name")
	rootCmd.PersistentFlags().Int("database-port", 5432, "database port")
	rootCmd.PersistentFlags().String("database-hostname", "localhost", "database hostname")
	rootCmd.PersistentFlags().String("database-user", "", "database user")
	rootCmd.PersistentFlags().String("database-password", "", "database password")
	rootCmd.PersistentFlags().String("client-ipcPath", "", "location of geth.ipc file")
	rootCmd.PersistentFlags().String("log-level", log.InfoLevel.String(), "Log level (trace, debug, info, warn, error, fatal, panic")

	rootCmd.PersistentFlags().Bool("metrics", false, "enable metrics")

	rootCmd.PersistentFlags().Bool("http", false, "enable http service for prometheus")
	rootCmd.PersistentFlags().String("http-addr", "127.0.0.1", "http host for prometheus")
	rootCmd.PersistentFlags().String("http-port", "8090", "http port for prometheus")

	viper.BindPFlag("logfile", rootCmd.PersistentFlags().Lookup("logfile"))
	viper.BindPFlag("database.name", rootCmd.PersistentFlags().Lookup("database-name"))
	viper.BindPFlag("database.port", rootCmd.PersistentFlags().Lookup("database-port"))
	viper.BindPFlag("database.hostname", rootCmd.PersistentFlags().Lookup("database-hostname"))
	viper.BindPFlag("database.user", rootCmd.PersistentFlags().Lookup("database-user"))
	viper.BindPFlag("database.password", rootCmd.PersistentFlags().Lookup("database-password"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))

	viper.BindPFlag("metrics", rootCmd.PersistentFlags().Lookup("metrics"))

	viper.BindPFlag("http", rootCmd.PersistentFlags().Lookup("http"))
	viper.BindPFlag("http.addr", rootCmd.PersistentFlags().Lookup("http-addr"))
	viper.BindPFlag("http.port", rootCmd.PersistentFlags().Lookup("http-port"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err == nil {
			log.Printf("Using config file: %s", viper.ConfigFileUsed())
		} else {
			log.Fatal(fmt.Sprintf("Couldn't read config file: %s", err.Error()))
		}
	} else {
		log.Warn("No config file passed with --config flag")
	}
}
