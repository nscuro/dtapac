package apply

import "github.com/prometheus/client_golang/prometheus"

var (
	totalApplied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dtapac",
		Name:      "analyses_applied_total",
		Help:      "Total number of applied analyses",
	}, []string{"status", "type"})
)

const (
	metricsLabelStatusFailed  = "failed"
	metricsLabelStatusNop     = "noop"
	metricsLabelStatusSuccess = "success"
)

const (
	metricsLabelTypeFinding   = "finding"
	metricsLabelTypeViolation = "violation"
)

//nolint:gochecknoinits
func init() {
	prometheus.MustRegister(totalApplied)
}
