package prom

import (
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace = "ipld_eth_server"

	subsystemHTTP = "http"
	subsystemWS   = "ws"
	subsystemIPC  = "ipc"
)

var (
	metrics bool

	httpCount    prometheus.Counter
	httpDuration prometheus.Histogram
	wsCount      prometheus.Gauge
	ipcCount     prometheus.Gauge
)

// Init module initialization
func Init() {
	metrics = true

	httpCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystemHTTP,
		Name:      "count",
		Help:      "http request count",
	})
	httpDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystemHTTP,
		Name:      "duration",
		Help:      "http request duration",
	})

	wsCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystemWS,
		Name:      "count",
		Help:      "websocket connection count",
	})

	ipcCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystemIPC,
		Name:      "count",
		Help:      "unix socket connection count",
	})
}

// RegisterDBCollector create metric colletor for given connection
func RegisterDBCollector(name string, db *sqlx.DB) {
	if metrics {
		prometheus.Register(NewDBStatsCollector(name, db))
	}
}
