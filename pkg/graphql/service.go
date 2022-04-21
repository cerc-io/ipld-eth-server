// VulcanizeDB
// Copyright © 2020 Vulcanize

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

package graphql

import (
	"fmt"
	"net"
	"net/http"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/relay"
	"github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
)

// Service encapsulates a GraphQL service.
type Service struct {
	endpoint string           // The host:port endpoint for this service.
	cors     []string         // Allowed CORS domains
	vhosts   []string         // Recognised vhosts
	timeouts rpc.HTTPTimeouts // Timeout settings for HTTP requests.
	backend  *eth.Backend     // The backend that queries will operate onn.
	handler  http.Handler     // The `http.Handler` used to answer queries.
	listener net.Listener     // The listening socket.
}

// New constructs a new GraphQL service instance.
func New(backend *eth.Backend, endpoint string, cors, vhosts []string, timeouts rpc.HTTPTimeouts) (*Service, error) {
	return &Service{
		endpoint: endpoint,
		cors:     cors,
		vhosts:   vhosts,
		timeouts: timeouts,
		backend:  backend,
	}, nil
}

// Protocols returns the list of protocols exported by this service.
func (s *Service) Protocols() []p2p.Protocol { return nil }

// APIs returns the list of APIs exported by this service.
func (s *Service) APIs() []rpc.API { return nil }

// Start is called after all services have been constructed and the networking
// layer was also initialized to spawn any goroutines required by the service.
func (s *Service) Start(server *p2p.Server) error {
	var err error
	s.handler, err = NewHandler(s.backend)
	if err != nil {
		return err
	}

	handler := node.NewHTTPHandlerStack(s.handler, s.cors, s.vhosts, nil)

	// start http server
	_, addr, err := node.StartHTTPEndpoint(s.endpoint, rpc.DefaultHTTPTimeouts, handler)
	if err != nil {
		utils.Fatalf("Could not start RPC api: %v", err)
	}
	extapiURL := fmt.Sprintf("http://%v/", addr)
	logrus.Infof("graphQL endpoint opened for url %s", extapiURL)
	return nil
}

// newHandler returns a new `http.Handler` that will answer GraphQL queries.
// It additionally exports an interactive query browser on the / endpoint.
func NewHandler(backend *eth.Backend) (http.Handler, error) {
	q := Resolver{backend}

	s, err := graphql.ParseSchema(schema, &q)
	if err != nil {
		return nil, err
	}
	h := &relay.Handler{Schema: s}

	mux := http.NewServeMux()
	mux.Handle("/", GraphiQL{})
	mux.Handle("/graphql", h)
	mux.Handle("/graphql/", h)
	return mux, nil
}

// Stop terminates all goroutines belonging to the service, blocking until they
// are all terminated.
func (s *Service) Stop() error {
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
		logrus.Debugf("graphQL endpoint closed for url %s", fmt.Sprintf("http://%s", s.endpoint))
	}
	return nil
}
