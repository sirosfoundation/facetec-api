// Package metrics provides IPV-specific Prometheus metrics for facetec-api.
//
// All metrics use the "facetec_" prefix and are safe to expose — no PII or
// biometric data appears in labels or values.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// IPV holds all IPV-specific Prometheus metrics.
type IPV struct {
	SessionsTotal          *prometheus.CounterVec
	LivenessScore          prometheus.Histogram
	FaceMatchLevel         prometheus.Histogram
	DocumentTypeTotal      *prometheus.CounterVec
	PolicyEvalDuration     prometheus.Histogram
	SessionDuration        *prometheus.HistogramVec
	QualityRejectionsTotal *prometheus.CounterVec
}

// New registers and returns the IPV metrics using the default registerer.
func New() *IPV {
	return NewWith(prometheus.DefaultRegisterer)
}

// NewWith registers and returns the IPV metrics using the given registerer.
// Use this in tests to avoid mutating global state.
func NewWith(reg prometheus.Registerer) *IPV {
	factory := promauto.With(reg)
	return &IPV{
		SessionsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "facetec_ipv_sessions_total",
			Help: "Total IPV sessions by outcome, tenant, and document type.",
		}, []string{"outcome", "tenant", "doc_type"}),

		LivenessScore: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "facetec_liveness_score",
			Help:    "Distribution of liveness scores (0.0–1.0).",
			Buckets: []float64{0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0},
		}),

		FaceMatchLevel: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "facetec_face_match_level",
			Help:    "Distribution of face match levels (0–10).",
			Buckets: []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		}),

		DocumentTypeTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "facetec_document_type_total",
			Help: "Total documents processed by type.",
		}, []string{"type"}),

		PolicyEvalDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "facetec_policy_evaluation_duration_seconds",
			Help:    "Time spent evaluating SPOCP policy rules.",
			Buckets: prometheus.DefBuckets,
		}),

		SessionDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "facetec_session_duration_seconds",
			Help:    "End-to-end IPV session duration by outcome.",
			Buckets: []float64{1, 2, 5, 10, 15, 30, 60, 120},
		}, []string{"outcome"}),

		QualityRejectionsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "facetec_quality_rejections_total",
			Help: "Total sessions rejected due to capture quality.",
		}, []string{"reason"}),
	}
}

// ObserveSession records all metrics for a completed IPV session.
func (m *IPV) ObserveSession(outcome, tenant, docType string, livenessScore float64, faceMatchLevel int, duration time.Duration) {
	m.SessionsTotal.WithLabelValues(outcome, tenant, docType).Inc()
	m.LivenessScore.Observe(livenessScore)
	m.FaceMatchLevel.Observe(float64(faceMatchLevel))
	m.DocumentTypeTotal.WithLabelValues(docType).Inc()
	m.SessionDuration.WithLabelValues(outcome).Observe(duration.Seconds())
}

// ObservePolicyEval records the duration of a policy evaluation.
func (m *IPV) ObservePolicyEval(duration time.Duration) {
	m.PolicyEvalDuration.Observe(duration.Seconds())
}

// ObserveQualityRejection increments the quality rejection counter.
func (m *IPV) ObserveQualityRejection(reason string) {
	m.QualityRejectionsTotal.WithLabelValues(reason).Inc()
}
