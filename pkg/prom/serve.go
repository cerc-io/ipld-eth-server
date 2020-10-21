package prom

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
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
			logrus.
				WithError(err).
				WithField("module", "prom").
				WithField("addr", addr).
				Fatal(errPromHTTP)
		}
	}()
	return &srv
}
