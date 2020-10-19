package prom

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

func HTTPMiddleware(next http.Handler) http.Handler {
	if !metrics {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCount.Inc()

		timer := prometheus.NewTimer(httpDuration)
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}

func WSMiddleware(next http.Handler) http.Handler {
	if !metrics {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsCount.Inc()

		timer := prometheus.NewTimer(wsDuration)
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}
