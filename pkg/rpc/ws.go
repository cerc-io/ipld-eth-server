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

package rpc

import (
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/node"
	"net"
	"net/http"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"
)

// StartWSEndpoint starts a websocket endpoint.
func StartWSEndpoint(endpoint string, apis []rpc.API, modules []string, wsOrigins []string, exposeAll bool) (net.Listener, *rpc.Server, error) {
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)

	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	err = node.RegisterApisFromWhitelist(apis, modules, handler, exposeAll)
	if err != nil {
		utils.Fatalf("Could not register WS API: %w", err)
	}

	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return nil, nil, err
	}

	wsServer := NewWSServer(wsOrigins, handler)
	wsServer.Handler = prom.WSMiddleware(wsServer.Handler)
	go wsServer.Serve(listener)

	return listener, handler, err

}

// NewWSServer creates a new websocket RPC server around an API provider.
//
// Deprecated: use prc.Server.WebsocketHandler
func NewWSServer(allowedOrigins []string, srv *rpc.Server) *http.Server {
	return &http.Server{Handler: srv.WebsocketHandler(allowedOrigins)}
}
