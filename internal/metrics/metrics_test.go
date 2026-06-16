package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func TestObserveSession(t *testing.T) {
	// Reset default registry for test isolation
	reg := prometheus.NewRegistry()
	origRegisterer := prometheus.DefaultRegisterer
	origGatherer := prometheus.DefaultGatherer
	prometheus.DefaultRegisterer = reg
	prometheus.DefaultGatherer = reg
	defer func() {
		prometheus.DefaultRegisterer = origRegisterer
		prometheus.DefaultGatherer = origGatherer
	}()

	m := New()
	m.ObserveSession("accept", "default", "passport", 0.92, 8, 5*time.Second)

	// Verify counter incremented
	ch := make(chan prometheus.Metric, 10)
	m.SessionsTotal.Collect(ch)
	close(ch)
	metric := <-ch
	var dto io_prometheus_client.Metric
	if err := metric.Write(&dto); err != nil {
		t.Fatal(err)
	}
	if got := dto.GetCounter().GetValue(); got != 1.0 {
		t.Errorf("sessions_total = %f, want 1.0", got)
	}
}

func TestObservePolicyEval(t *testing.T) {
	reg := prometheus.NewRegistry()
	origRegisterer := prometheus.DefaultRegisterer
	origGatherer := prometheus.DefaultGatherer
	prometheus.DefaultRegisterer = reg
	prometheus.DefaultGatherer = reg
	defer func() {
		prometheus.DefaultRegisterer = origRegisterer
		prometheus.DefaultGatherer = origGatherer
	}()

	m := New()
	m.ObservePolicyEval(50 * time.Millisecond)
	// No panic = pass
}
