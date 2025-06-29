package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector handles metrics collection for the API Gateway
type Collector struct {
	// HTTP metrics
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	requestsInFlight prometheus.Gauge
	responseSize     *prometheus.HistogramVec

	// Gateway specific metrics
	upstreamRequests  *prometheus.CounterVec
	upstreamDuration  *prometheus.HistogramVec
	upstreamErrors    *prometheus.CounterVec
	activeConnections prometheus.Gauge

	// Authentication metrics
	authAttempts     *prometheus.CounterVec
	tokenValidations *prometheus.CounterVec

	// Rate limiting metrics
	rateLimitHits *prometheus.CounterVec

	// Health check metrics
	healthChecks   *prometheus.CounterVec
	upstreamHealth *prometheus.GaugeVec

	// System metrics
	startTime prometheus.Gauge
	buildInfo *prometheus.GaugeVec

	mu sync.RWMutex
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	collector := &Collector{
		// HTTP request metrics
		requestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_http_requests_total",
				Help: "Total number of HTTP requests processed by the gateway",
			},
			[]string{"method", "path", "status_code"},
		),

		requestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path", "status_code"},
		),

		requestsInFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_http_requests_in_flight",
				Help: "Number of HTTP requests currently being processed",
			},
		),

		responseSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_http_response_size_bytes",
				Help:    "HTTP response size in bytes",
				Buckets: []float64{100, 1000, 10000, 100000, 1000000},
			},
			[]string{"method", "path", "status_code"},
		),

		// Upstream service metrics
		upstreamRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_upstream_requests_total",
				Help: "Total number of requests sent to upstream services",
			},
			[]string{"service", "instance", "status_code"},
		),

		upstreamDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_upstream_request_duration_seconds",
				Help:    "Upstream request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"service", "instance"},
		),

		upstreamErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_upstream_errors_total",
				Help: "Total number of upstream service errors",
			},
			[]string{"service", "instance", "error_type"},
		),

		activeConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_active_connections",
				Help: "Number of active connections to the gateway",
			},
		),

		// Authentication metrics
		authAttempts: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_auth_attempts_total",
				Help: "Total number of authentication attempts",
			},
			[]string{"method", "status"},
		),

		tokenValidations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_token_validations_total",
				Help: "Total number of token validations",
			},
			[]string{"status"},
		),

		// Rate limiting metrics
		rateLimitHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_rate_limit_hits_total",
				Help: "Total number of rate limit hits",
			},
			[]string{"key_type", "action"},
		),

		// Health check metrics
		healthChecks: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_health_checks_total",
				Help: "Total number of health checks performed",
			},
			[]string{"service", "instance", "status"},
		),

		upstreamHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_upstream_health",
				Help: "Health status of upstream services (1=healthy, 0=unhealthy)",
			},
			[]string{"service", "instance"},
		),

		// System metrics
		startTime: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_start_time_seconds",
				Help: "Unix timestamp when the gateway started",
			},
		),

		buildInfo: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_build_info",
				Help: "Build information about the gateway",
			},
			[]string{"version", "commit", "build_date"},
		),
	}

	// Set start time
	collector.startTime.SetToCurrentTime()

	// Set build info (you can make these configurable)
	collector.buildInfo.WithLabelValues("1.0.0", "dev", time.Now().Format("2006-01-02")).Set(1)

	return collector
}

// RecordRequest records HTTP request metrics
func (c *Collector) RecordRequest(method, path string, statusCode int, duration time.Duration) {
	statusStr := c.statusCode(statusCode)

	c.requestsTotal.WithLabelValues(method, path, statusStr).Inc()
	c.requestDuration.WithLabelValues(method, path, statusStr).Observe(duration.Seconds())
}

// RecordResponseSize records HTTP response size
func (c *Collector) RecordResponseSize(method, path string, statusCode int, size int64) {
	statusStr := c.statusCode(statusCode)
	c.responseSize.WithLabelValues(method, path, statusStr).Observe(float64(size))
}

// IncRequestsInFlight increments the in-flight requests counter
func (c *Collector) IncRequestsInFlight() {
	c.requestsInFlight.Inc()
}

// DecRequestsInFlight decrements the in-flight requests counter
func (c *Collector) DecRequestsInFlight() {
	c.requestsInFlight.Dec()
}

// RecordUpstreamRequest records upstream service request metrics
func (c *Collector) RecordUpstreamRequest(service, instance string, statusCode int, duration time.Duration) {
	statusStr := c.statusCode(statusCode)

	c.upstreamRequests.WithLabelValues(service, instance, statusStr).Inc()
	c.upstreamDuration.WithLabelValues(service, instance).Observe(duration.Seconds())
}

// RecordUpstreamError records upstream service errors
func (c *Collector) RecordUpstreamError(service, instance, errorType string) {
	c.upstreamErrors.WithLabelValues(service, instance, errorType).Inc()
}

// SetActiveConnections sets the number of active connections
func (c *Collector) SetActiveConnections(count int) {
	c.activeConnections.Set(float64(count))
}

// RecordAuthAttempt records authentication attempts
func (c *Collector) RecordAuthAttempt(method, status string) {
	c.authAttempts.WithLabelValues(method, status).Inc()
}

// RecordTokenValidation records token validation attempts
func (c *Collector) RecordTokenValidation(status string) {
	c.tokenValidations.WithLabelValues(status).Inc()
}

// RecordRateLimitHit records rate limit hits
func (c *Collector) RecordRateLimitHit(keyType, action string) {
	c.rateLimitHits.WithLabelValues(keyType, action).Inc()
}

// RecordHealthCheck records health check results
func (c *Collector) RecordHealthCheck(service, instance, status string) {
	c.healthChecks.WithLabelValues(service, instance, status).Inc()
}

// SetUpstreamHealth sets the health status of an upstream service
func (c *Collector) SetUpstreamHealth(service, instance string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	c.upstreamHealth.WithLabelValues(service, instance).Set(value)
}

// GetStats returns current metrics statistics
func (c *Collector) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// This is a simplified version - in production you'd gather actual metric values
	stats := map[string]interface{}{
		"requests_total":     "See /metrics endpoint",
		"requests_in_flight": "See /metrics endpoint",
		"upstream_services":  "See /metrics endpoint",
		"auth_attempts":      "See /metrics endpoint",
		"rate_limit_hits":    "See /metrics endpoint",
		"health_checks":      "See /metrics endpoint",
		"start_time":         time.Now().Add(-time.Hour), // Placeholder
		"uptime_seconds":     time.Hour.Seconds(),        // Placeholder
	}

	return stats
}

// Start initializes the metrics collector (placeholder for future background tasks)
func (c *Collector) Start() {
	// Future: Start background metric collection tasks
	// For now, metrics are collected on-demand
}

// Stop gracefully stops the metrics collector
func (c *Collector) Stop() {
	// Future: Stop background metric collection tasks
	// For now, nothing to stop
}

// Custom prometheus status code function
func (c *Collector) statusCode(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "unknown"
	}
}

// RequestMetricsMiddleware returns a function that can be used as middleware
func (c *Collector) RequestMetricsMiddleware() func(next func()) {
	return func(next func()) {
		c.IncRequestsInFlight()
		defer c.DecRequestsInFlight()
		next()
	}
}

// Summary provides a summary of key metrics
type Summary struct {
	TotalRequests     int64   `json:"total_requests"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	AverageLatency    float64 `json:"average_latency_ms"`
	ErrorRate         float64 `json:"error_rate_percent"`
	UpstreamServices  int     `json:"upstream_services"`
	HealthyServices   int     `json:"healthy_services"`
	ActiveConnections int     `json:"active_connections"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
}

// GetSummary returns a summary of key metrics
func (c *Collector) GetSummary() *Summary {
	// This is a placeholder implementation
	// In a real implementation, you'd calculate these from the actual metrics
	uptime := time.Hour.Seconds() // Placeholder

	return &Summary{
		TotalRequests:     0, // Would be calculated from actual metrics
		RequestsPerSecond: 0, // Would be calculated from actual metrics
		AverageLatency:    0, // Would be calculated from actual metrics
		ErrorRate:         0, // Would be calculated from actual metrics
		UpstreamServices:  0, // Would be calculated from actual metrics
		HealthyServices:   0, // Would be calculated from actual metrics
		ActiveConnections: 0, // Would be calculated from actual metrics
		UptimeSeconds:     uptime,
	}
}
