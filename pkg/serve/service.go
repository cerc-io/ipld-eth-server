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

package serve

import (
	"strconv"
	"sync"
	"time"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	ethnode "github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jmoiron/sqlx"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/debug"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/eth"
	"github.com/cerc-io/ipld-eth-server/v4/pkg/net"
)

const (
	PayloadChanBufferSize = 2000
)

// Server is the top level interface for streaming, converting to IPLDs, publishing,
// and indexing all chain data; screening this data; and serving it up to subscribed clients
// This service is compatible with the Ethereum service interface (node.Service)
type Server interface {
	// Start() and Stop()
	ethnode.Lifecycle
	APIs() []rpc.API
	Protocols() []p2p.Protocol
	// Pub-Sub handling event loop
	Serve(wg *sync.WaitGroup)
	// Backend exposes the server's backend
	Backend() *eth.Backend
}

// Service is the underlying struct for the watcher
type Service struct {
	// Used to sync access to the Subscriptions
	sync.Mutex
	// Used to signal shutdown of the service
	QuitChan chan bool
	// Underlying db connection pool
	db *sqlx.DB
	// rpc client for forwarding cache misses
	client *rpc.Client
	// whether the proxied client supports state diffing
	supportsStateDiffing bool
	// timeout for statediff RPC calls
	stateDiffTimeout time.Duration
	// backend for the server
	backend *eth.Backend
	// whether to forward eth_calls directly to proxy node
	forwardEthCalls bool
	// whether to forward eth_getStorageAt directly to proxy node
	forwardGetStorageAt bool
	// whether to forward all calls to proxy node if they throw an error locally
	proxyOnError bool
	// eth node network id
	nodeNetworkId string
}

// NewServer creates a new Server using an underlying Service struct
func NewServer(settings *Config) (Server, error) {
	sap := new(Service)
	sap.db = settings.DB
	sap.QuitChan = make(chan bool)
	sap.client = settings.Client
	sap.supportsStateDiffing = settings.SupportStateDiff
	sap.stateDiffTimeout = settings.StateDiffTimeout
	sap.forwardEthCalls = settings.ForwardEthCalls
	sap.forwardGetStorageAt = settings.ForwardGetStorageAt
	sap.proxyOnError = settings.ProxyOnError
	sap.nodeNetworkId = settings.NodeNetworkID
	var err error
	sap.backend, err = eth.NewEthBackend(sap.db, &eth.Config{
		ChainConfig:      settings.ChainConfig,
		VMConfig:         vm.Config{NoBaseFee: true},
		DefaultSender:    settings.DefaultSender,
		RPCGasCap:        settings.RPCGasCap,
		GroupCacheConfig: settings.GroupCache,
	})
	return sap, err
}

// Protocols exports the services p2p protocols, this service has none
func (sap *Service) Protocols() []p2p.Protocol {
	return []p2p.Protocol{}
}

// APIs returns the RPC descriptors the watcher service offers
func (sap *Service) APIs() []rpc.API {
	networkID, _ := strconv.ParseUint(sap.nodeNetworkId, 10, 64)
	apis := []rpc.API{
		{
			Namespace: APIName,
			Version:   APIVersion,
			Service:   NewPublicServerAPI(sap, sap.client),
			Public:    true,
		},
		{
			Namespace: net.APIName,
			Version:   net.APIVersion,
			Service:   net.NewPublicNetAPI(networkID, sap.client),
			Public:    true,
		},
	}
	conf := eth.APIConfig{
		SupportsStateDiff:   sap.supportsStateDiffing,
		ForwardEthCalls:     sap.forwardEthCalls,
		ForwardGetStorageAt: sap.forwardGetStorageAt,
		ProxyOnError:        sap.proxyOnError,
		StateDiffTimeout:    sap.stateDiffTimeout,
	}
	ethAPI, err := eth.NewPublicEthAPI(sap.backend, sap.client, conf)
	if err != nil {
		log.Fatalf("unable to create public eth api: %v", err)
	}

	debugTracerAPI := tracers.APIs(&debug.Backend{Backend: *sap.backend})[0]

	return append(apis,
		rpc.API{
			Namespace: eth.APIName,
			Version:   eth.APIVersion,
			Service:   ethAPI,
			Public:    true,
		},
		debugTracerAPI,
	)
}

// Serve listens for incoming converter data off the screenAndServePayload from the Sync process
// It filters and sends this data to any subscribers to the service
// This process can also be stood up alone, without an screenAndServePayload attached to a Sync process
// and it will hang on the WaitGroup indefinitely, allowing the Service to serve historical data requests only
func (sap *Service) Serve(wg *sync.WaitGroup) {
	go func() {
		wg.Add(1)
		defer wg.Done()
		<-sap.QuitChan
		log.Info("quiting eth ipld server process")
	}()
	log.Info("eth ipld server process successfully spun up")
}

// Start is used to begin the service
// This is mostly just to satisfy the node.Service interface
func (sap *Service) Start() error {
	log.Info("starting eth ipld server")
	wg := new(sync.WaitGroup)
	sap.Serve(wg)
	return nil
}

// Stop is used to close down the service
// This is mostly just to satisfy the node.Service interface
func (sap *Service) Stop() error {
	log.Infof("stopping eth ipld server")
	sap.Lock()
	close(sap.QuitChan)
	sap.Unlock()
	return nil
}

// Backend exposes the server's backend
func (sap *Service) Backend() *eth.Backend {
	return sap.backend
}
