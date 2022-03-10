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

package test_config

import (
	"errors"

	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql/postgres"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var DBConfig postgres.Config

func init() {
	setTestConfig()
}

func setTestConfig() {
	vip := viper.New()
	vip.SetConfigName("testing")
	vip.AddConfigPath("$GOPATH/src/github.com/vulcanize/ipld-eth-server/environments/")
	if err := vip.ReadInConfig(); err != nil {
		logrus.Fatal(err)
	}
	ipc := vip.GetString("client.ipcPath")

	// If we don't have an ipc path in the config file, check the env variable
	if ipc == "" {
		vip.BindEnv("url", "INFURA_URL")
		ipc = vip.GetString("url")
	}
	if ipc == "" {
		logrus.Fatal(errors.New("testing.toml IPC path or $INFURA_URL env variable need to be set"))
	}

	hn := vip.GetString("database.hostname")
	port := vip.GetInt("database.port")
	name := vip.GetString("database.name")

	DBConfig = postgres.Config{
		Hostname:     hn,
		DatabaseName: name,
		Port:         port,
	}
}
