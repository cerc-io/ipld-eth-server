package prom

import (
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace      = "ipld_eth_server"
	statsSubsystem = "stats"
)

var (
	metrics bool
)

// Init module initialization
func Init() {
	metrics = true
}

// RegisterDBCollector create metric colletor for given connection
func RegisterDBCollector(name string, db *sqlx.DB) {
	if metrics {
		prometheus.Register(NewDBStatsCollector(name, db))
	}
}
