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

	wsCount    prometheus.Counter
	wsDuration prometheus.Histogram

	ipcCount    prometheus.Counter
	ipcDuration prometheus.Gauge
)

// Init module initialization
func Init() {
	metrics = true

	httpCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystemHTTP,
		Name:      "count",
		Help:      "",
	})
	httpDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystemHTTP,
		Name:      "duration",
		Help:      "",
	})

	wsCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystemWS,
		Name:      "count",
		Help:      "",
	})
	wsDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystemWS,
		Name:      "duration",
		Help:      "",
	})

	ipcCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystemIPC,
		Name:      "count",
		Help:      "",
	})
	ipcDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystemIPC,
		Name:      "duration",
		Help:      "",
	})
}

// RegisterDBCollector create metric colletor for given connection
func RegisterDBCollector(name string, db *sqlx.DB) {
	if metrics {
		prometheus.Register(NewDBStatsCollector(name, db))
	}
}
