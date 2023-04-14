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
	"errors"
	"net/http"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var errPromHTTP = errors.New("can't start http server for prometheus")

// Serve start listening http
func Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := http.Server{
		Addr:    addr,
		Handler: mux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.
				WithError(err).
				WithField("module", "prom").
				WithField("addr", addr).
				Fatal(errPromHTTP)
		}
	}()
	return &srv
}
