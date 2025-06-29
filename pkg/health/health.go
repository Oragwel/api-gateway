package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Oragwel/api-gateway/pkg/config"
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// Check represents a health check
type Check struct {
	Name        string                 `json:"name"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	LastCheck   time.Time              `json:"last_check"`
	Duration    time.Duration          `json:"duration"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CheckFunc   func() CheckResult     `json:"-"`
	Interval    time.Duration          `json:"-"`
	Timeout     time.Duration          `json:"-"`
	Enabled     bool                   `json:"-"`
}

// CheckResult represents the result of a health check
type CheckResult struct {
	Status   Status
	Message  string
	Metadata map[string]interface{}
}

// Report represents the overall health report
type Report struct {
	Status    Status             `json:"status"`
	Timestamp time.Time          `json:"timestamp"`
	Duration  time.Duration      `json:"duration"`
	Checks    map[string]*Check  `json:"checks"`
	Summary   map[string]int     `json:"summary"`
	Version   string             `json:"version"`
	Uptime    time.Duration      `json:"uptime"`
}

// Checker manages health checks for the API Gateway
type Checker struct {
	config    config.HealthConfig
	checks    map[string]*Check
	startTime time.Time
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewChecker creates a new health checker
func NewChecker(config config.HealthConfig) *Checker {
	ctx, cancel := context.WithCancel(context.Background())
	
	checker := &Checker{
		config:    config,
		checks:    make(map[string]*Check),
		startTime: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Register default checks
	checker.registerDefaultChecks()

	return checker
}

// registerDefaultChecks registers the default health checks
func (hc *Checker) registerDefaultChecks() {
	// System health check
	hc.RegisterCheck("system", &Check{
		Name:     "system",
		CheckFunc: hc.systemHealthCheck,
		Interval: 30 * time.Second,
		Timeout:  5 * time.Second,
		Enabled:  true,
	})

	// Memory health check
	hc.RegisterCheck("memory", &Check{
		Name:     "memory",
		CheckFunc: hc.memoryHealthCheck,
		Interval: 30 * time.Second,
		Timeout:  5 * time.Second,
		Enabled:  true,
	})

	// Database health check (placeholder)
	hc.RegisterCheck("database", &Check{
		Name:     "database",
		CheckFunc: hc.databaseHealthCheck,
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		Enabled:  false, // Disabled by default since we don't have a real database
	})

	// External dependencies check
	hc.RegisterCheck("dependencies", &Check{
		Name:     "dependencies",
		CheckFunc: hc.dependenciesHealthCheck,
		Interval: 60 * time.Second,
		Timeout:  15 * time.Second,
		Enabled:  true,
	})
}

// RegisterCheck registers a new health check
func (hc *Checker) RegisterCheck(name string, check *Check) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	check.Name = name
	check.Status = StatusUnknown
	check.LastCheck = time.Time{}
	
	if check.Interval == 0 {
		check.Interval = hc.config.CheckInterval
	}
	if check.Timeout == 0 {
		check.Timeout = hc.config.Timeout
	}

	hc.checks[name] = check
}

// Start starts the health checker
func (hc *Checker) Start() {
	if !hc.config.Enabled {
		return
	}

	hc.wg.Add(1)
	go hc.runPeriodicChecks()
}

// Stop stops the health checker
func (hc *Checker) Stop() {
	hc.cancel()
	hc.wg.Wait()
}

// runPeriodicChecks runs health checks periodically
func (hc *Checker) runPeriodicChecks() {
	defer hc.wg.Done()

	ticker := time.NewTicker(hc.config.CheckInterval)
	defer ticker.Stop()

	// Run initial checks
	hc.runAllChecks()

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.runAllChecks()
		}
	}
}

// runAllChecks runs all registered health checks
func (hc *Checker) runAllChecks() {
	hc.mu.RLock()
	checks := make([]*Check, 0, len(hc.checks))
	for _, check := range hc.checks {
		if check.Enabled {
			checks = append(checks, check)
		}
	}
	hc.mu.RUnlock()

	// Run checks concurrently
	var wg sync.WaitGroup
	for _, check := range checks {
		wg.Add(1)
		go func(c *Check) {
			defer wg.Done()
			hc.runCheck(c)
		}(check)
	}
	wg.Wait()
}

// runCheck runs a single health check
func (hc *Checker) runCheck(check *Check) {
	start := time.Now()
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(hc.ctx, check.Timeout)
	defer cancel()

	// Run the check in a goroutine to respect timeout
	resultChan := make(chan CheckResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- CheckResult{
					Status:  StatusUnhealthy,
					Message: fmt.Sprintf("Health check panicked: %v", r),
				}
			}
		}()
		resultChan <- check.CheckFunc()
	}()

	var result CheckResult
	select {
	case result = <-resultChan:
		// Check completed normally
	case <-ctx.Done():
		// Check timed out
		result = CheckResult{
			Status:  StatusUnhealthy,
			Message: "Health check timed out",
		}
	}

	// Update check with result
	hc.mu.Lock()
	check.Status = result.Status
	check.Message = result.Message
	check.Metadata = result.Metadata
	check.LastCheck = start
	check.Duration = time.Since(start)
	hc.mu.Unlock()
}

// GetReport returns the current health report
func (hc *Checker) GetReport() *Report {
	start := time.Now()
	
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	// Copy checks
	checks := make(map[string]*Check)
	summary := map[string]int{
		"healthy":   0,
		"unhealthy": 0,
		"degraded":  0,
		"unknown":   0,
	}

	overallStatus := StatusHealthy
	for name, check := range hc.checks {
		if !check.Enabled {
			continue
		}

		// Create a copy of the check
		checkCopy := *check
		checks[name] = &checkCopy

		// Update summary
		summary[string(check.Status)]++

		// Determine overall status
		switch check.Status {
		case StatusUnhealthy:
			overallStatus = StatusUnhealthy
		case StatusDegraded:
			if overallStatus == StatusHealthy {
				overallStatus = StatusDegraded
			}
		case StatusUnknown:
			if overallStatus == StatusHealthy {
				overallStatus = StatusUnknown
			}
		}
	}

	return &Report{
		Status:    overallStatus,
		Timestamp: start,
		Duration:  time.Since(start),
		Checks:    checks,
		Summary:   summary,
		Version:   "1.0.0",
		Uptime:    time.Since(hc.startTime),
	}
}

// IsHealthy returns true if the system is healthy
func (hc *Checker) IsHealthy() bool {
	report := hc.GetReport()
	return report.Status == StatusHealthy
}

// IsReady returns true if the system is ready to serve requests
func (hc *Checker) IsReady() bool {
	report := hc.GetReport()
	return report.Status == StatusHealthy || report.Status == StatusDegraded
}

// Default health check implementations

// systemHealthCheck checks basic system health
func (hc *Checker) systemHealthCheck() CheckResult {
	// Basic system check - always healthy for this demo
	return CheckResult{
		Status:  StatusHealthy,
		Message: "System is running normally",
		Metadata: map[string]interface{}{
			"uptime_seconds": time.Since(hc.startTime).Seconds(),
			"goroutines":     "N/A", // Would use runtime.NumGoroutine() in real implementation
		},
	}
}

// memoryHealthCheck checks memory usage
func (hc *Checker) memoryHealthCheck() CheckResult {
	// Simplified memory check
	// In a real implementation, you'd check actual memory usage
	return CheckResult{
		Status:  StatusHealthy,
		Message: "Memory usage is within acceptable limits",
		Metadata: map[string]interface{}{
			"memory_usage_percent": 45.2, // Mock data
			"available_memory_mb":  1024,  // Mock data
		},
	}
}

// databaseHealthCheck checks database connectivity
func (hc *Checker) databaseHealthCheck() CheckResult {
	// Placeholder database check
	// In a real implementation, you'd ping your database
	return CheckResult{
		Status:  StatusHealthy,
		Message: "Database connection is healthy",
		Metadata: map[string]interface{}{
			"connection_pool_size": 10,
			"active_connections":   3,
		},
	}
}

// dependenciesHealthCheck checks external dependencies
func (hc *Checker) dependenciesHealthCheck() CheckResult {
	// Check external dependencies
	// This is a simplified version
	dependencies := []string{
		"https://httpbin.org/status/200", // Example external service
	}

	healthyCount := 0
	totalCount := len(dependencies)

	for _, dep := range dependencies {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(dep)
		if err == nil && resp.StatusCode == 200 {
			healthyCount++
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	status := StatusHealthy
	message := "All dependencies are healthy"

	if healthyCount == 0 {
		status = StatusUnhealthy
		message = "All dependencies are unhealthy"
	} else if healthyCount < totalCount {
		status = StatusDegraded
		message = fmt.Sprintf("%d of %d dependencies are healthy", healthyCount, totalCount)
	}

	return CheckResult{
		Status:  status,
		Message: message,
		Metadata: map[string]interface{}{
			"healthy_dependencies": healthyCount,
			"total_dependencies":   totalCount,
			"dependency_urls":      dependencies,
		},
	}
}
