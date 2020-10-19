package rpc

import (
	"C"

	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"
)

var (
	//  On Linux, sun_path is 108 bytes in size
	// see http://man7.org/linux/man-pages/man7/unix.7.html
	maxPathSize = 108
)

// ipcListen will create a Unix socket on the given endpoint.
func ipcListen(endpoint string) (net.Listener, error) {
	if len(endpoint) > int(maxPathSize) {
		log.Warn(fmt.Sprintf("The ipc endpoint is longer than %d characters. ", maxPathSize),
			"endpoint", endpoint)
	}

	// Ensure the IPC path exists and remove any previous leftover
	if err := os.MkdirAll(filepath.Dir(endpoint), 0751); err != nil {
		return nil, err
	}
	os.Remove(endpoint)
	l, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, err
	}
	os.Chmod(endpoint, 0600)
	return l, nil
}

// StartIPCEndpoint starts an IPC endpoint.
func StartIPCEndpoint(ipcEndpoint string, apis []rpc.API) (net.Listener, *rpc.Server, error) {
	// Register all the APIs exposed by the services.
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return nil, nil, err
		}
		log.Debug("IPC registered", "namespace", api.Namespace)
	}
	// All APIs registered, start the IPC listener.
	listener, err := ipcListen(ipcEndpoint)
	if err != nil {
		return nil, nil, err
	}
	go handler.ServeListener(listener)
	return listener, handler, nil
}
