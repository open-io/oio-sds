package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	prometheus.MustRegister(requestCounter)
}

var (
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rawx_request_count",
			Help: "Counter of rawx requests for each HTTP verb and HTTP response code",
		},
		[]string{"verb", "code", "resource"},
	)
)

func Monitor(verb string, httpCode int, resource string) {
	requestCounter.WithLabelValues(verb, itoa(httpCode), resource).Inc()
}
