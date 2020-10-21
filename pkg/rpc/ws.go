package rpc

import (
	"net"

	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"
)

// StartWSEndpoint starts a websocket endpoint.
func StartWSEndpoint(endpoint string, apis []rpc.API, modules []string, wsOrigins []string, exposeAll bool) (net.Listener, *rpc.Server, error) {
	if bad, available := checkModuleAvailability(modules, apis); len(bad) > 0 {
		log.Error("Unavailable modules in WS API list", "unavailable", bad, "available", available)
	}
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if exposeAll || whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return nil, nil, err
			}
			log.Debug("WebSocket registered", "service", api.Service, "namespace", api.Namespace)
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return nil, nil, err
	}

	wsServer := rpc.NewWSServer(wsOrigins, handler)
	wsServer.Handler = prom.WSMiddleware(wsServer.Handler)
	go wsServer.Serve(listener)

	return listener, handler, err

}
