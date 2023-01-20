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

	httpCount    *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	wsCount      prometheus.Gauge
	ipcCount     prometheus.Gauge
)

// Init module initialization
func Init() {
	metrics = true

	httpCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystemHTTP,
		Name:      "count",
		Help:      "http request count",
	}, []string{"method"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystemHTTP,
		Name:      "duration",
		Help:      "http request duration",
	}, []string{"method"})

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
