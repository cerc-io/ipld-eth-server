package prom

import (
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
)

// HTTPMiddleware http connection metric reader
func HTTPMiddleware(next http.Handler) http.Handler {
	if !metrics {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCount.Inc()

		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Now().Sub(start)
		httpDuration.Observe(float64(duration.Seconds()))
	})
}

// WSMiddleware websocket connection counter
func WSMiddleware(next http.Handler) http.Handler {
	if !metrics {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsCount.Inc()
		next.ServeHTTP(w, r)
		wsCount.Dec()
	})
}

// IPCMiddleware unix-socket connection counter
func IPCMiddleware(server *rpc.Server, client rpc.Conn) {
	if metrics {
		ipcCount.Inc()
	}
	server.ServeCodec(rpc.NewCodec(client), 0)
	if metrics {
		ipcCount.Dec()
	}
}
