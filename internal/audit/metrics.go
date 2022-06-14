package audit

import "github.com/prometheus/client_golang/prometheus"

var (
	totalAudited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dtapac",
		Name:      "audited_total",
	}, []string{"status", "type"})
)

const (
	metricsLabelStatusSuccess   = "success"
	metricsLabelStatusFailed    = "failed"
	metricsLabelStatusUnmatched = "unmatched"
)

const (
	metricsLabelTypeFinding   = "finding"
	metricsLabelTypeViolation = "violation"
)

func init() {
	prometheus.MustRegister(totalAudited)
}
