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

package shared

import (
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/spf13/viper"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/node"
)

// Env variables
const (
	IPFS_PATH    = "IPFS_PATH"
	IPFS_MODE    = "IPFS_MODE"
	HTTP_TIMEOUT = "HTTP_TIMEOUT"

	ETH_WS_PATH       = "ETH_WS_PATH"
	ETH_HTTP_PATH     = "ETH_HTTP_PATH"
	ETH_NODE_ID       = "ETH_NODE_ID"
	ETH_CLIENT_NAME   = "ETH_CLIENT_NAME"
	ETH_GENESIS_BLOCK = "ETH_GENESIS_BLOCK"
	ETH_NETWORK_ID    = "ETH_NETWORK_ID"
	ETH_CHAIN_ID      = "ETH_CHAIN_ID"

	BTC_WS_PATH       = "BTC_WS_PATH"
	BTC_HTTP_PATH     = "BTC_HTTP_PATH"
	BTC_NODE_PASSWORD = "BTC_NODE_PASSWORD"
	BTC_NODE_USER     = "BTC_NODE_USER"
	BTC_NODE_ID       = "BTC_NODE_ID"
	BTC_CLIENT_NAME   = "BTC_CLIENT_NAME"
	BTC_GENESIS_BLOCK = "BTC_GENESIS_BLOCK"
	BTC_NETWORK_ID    = "BTC_NETWORK_ID"
	BTC_CHAIN_ID      = "BTC_CHAIN_ID"
)

// GetEthNodeAndClient returns eth node info and client from path url
func GetEthNodeAndClient(path string) (node.Node, *rpc.Client, error) {
	viper.BindEnv("ethereum.nodeID", ETH_NODE_ID)
	viper.BindEnv("ethereum.clientName", ETH_CLIENT_NAME)
	viper.BindEnv("ethereum.genesisBlock", ETH_GENESIS_BLOCK)
	viper.BindEnv("ethereum.networkID", ETH_NETWORK_ID)
	viper.BindEnv("ethereum.chainID", ETH_CHAIN_ID)

	rpcClient, err := rpc.Dial(path)
	if err != nil {
		return node.Node{}, nil, err
	}
	return node.Node{
		ID:           viper.GetString("ethereum.nodeID"),
		ClientName:   viper.GetString("ethereum.clientName"),
		GenesisBlock: viper.GetString("ethereum.genesisBlock"),
		NetworkID:    viper.GetString("ethereum.networkID"),
		ChainID:      viper.GetUint64("ethereum.chainID"),
	}, rpcClient, nil
}

// GetIPFSPath returns the ipfs path from the config or env variable
func GetIPFSPath() (string, error) {
	viper.BindEnv("ipfs.path", IPFS_PATH)
	ipfsPath := viper.GetString("ipfs.path")
	if ipfsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		ipfsPath = filepath.Join(home, ".ipfs")
	}
	return ipfsPath, nil
}

// GetIPFSMode returns the ipfs mode of operation from the config or env variable
func GetIPFSMode() (IPFSMode, error) {
	viper.BindEnv("ipfs.mode", IPFS_MODE)
	ipfsMode := viper.GetString("ipfs.mode")
	if ipfsMode == "" {
		return DirectPostgres, nil
	}
	return NewIPFSMode(ipfsMode)
}

// GetBtcNodeAndClient returns btc node info from path url
func GetBtcNodeAndClient(path string) (node.Node, *rpcclient.ConnConfig) {
	viper.BindEnv("bitcoin.nodeID", BTC_NODE_ID)
	viper.BindEnv("bitcoin.clientName", BTC_CLIENT_NAME)
	viper.BindEnv("bitcoin.genesisBlock", BTC_GENESIS_BLOCK)
	viper.BindEnv("bitcoin.networkID", BTC_NETWORK_ID)
	viper.BindEnv("bitcoin.pass", BTC_NODE_PASSWORD)
	viper.BindEnv("bitcoin.user", BTC_NODE_USER)
	viper.BindEnv("bitcoin.chainID", BTC_CHAIN_ID)

	// For bitcoin we load in node info from the config because there is no RPC endpoint to retrieve this from the node
	return node.Node{
			ID:           viper.GetString("bitcoin.nodeID"),
			ClientName:   viper.GetString("bitcoin.clientName"),
			GenesisBlock: viper.GetString("bitcoin.genesisBlock"),
			NetworkID:    viper.GetString("bitcoin.networkID"),
			ChainID:      viper.GetUint64("bitcoin.chainID"),
		}, &rpcclient.ConnConfig{
			Host:         path,
			HTTPPostMode: true, // Bitcoin core only supports HTTP POST mode
			DisableTLS:   true, // Bitcoin core does not provide TLS by default
			Pass:         viper.GetString("bitcoin.pass"),
			User:         viper.GetString("bitcoin.user"),
		}
}
