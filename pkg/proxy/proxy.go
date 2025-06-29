package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/Oragwel/api-gateway/pkg/config"
)

// Pool manages upstream service connections and load balancing
type Pool struct {
	services map[string]*Service
	mu       sync.RWMutex
}

// Service represents an upstream service with load balancing
type Service struct {
	Name         string
	Config       config.ServiceConfig
	Instances    []*Instance
	LoadBalancer LoadBalancer
	mu           sync.RWMutex
}

// Instance represents a single service instance
type Instance struct {
	URL       *url.URL
	Weight    int
	Health    HealthStatus
	Proxy     *httputil.ReverseProxy
	LastCheck time.Time
	mu        sync.RWMutex
}

// HealthStatus represents the health status of an instance
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// LoadBalancer interface for different load balancing strategies
type LoadBalancer interface {
	NextInstance(instances []*Instance) *Instance
	Name() string
}

// RoundRobinBalancer implements round-robin load balancing
type RoundRobinBalancer struct {
	current int
	mu      sync.Mutex
}

// LeastConnectionsBalancer implements least connections load balancing
type LeastConnectionsBalancer struct {
	connections map[string]int
	mu          sync.Mutex
}

// WeightedRoundRobinBalancer implements weighted round-robin load balancing
type WeightedRoundRobinBalancer struct {
	current int
	weights []int
	mu      sync.Mutex
}

// NewPool creates a new proxy pool
func NewPool(config config.UpstreamConfig) *Pool {
	pool := &Pool{
		services: make(map[string]*Service),
	}

	// Initialize services
	for name, serviceConfig := range config.Services {
		service := &Service{
			Name:      name,
			Config:    serviceConfig,
			Instances: make([]*Instance, 0),
		}

		// Initialize load balancer
		switch serviceConfig.LoadBalancer {
		case "least_conn":
			service.LoadBalancer = &LeastConnectionsBalancer{
				connections: make(map[string]int),
			}
		case "weighted_round_robin":
			service.LoadBalancer = &WeightedRoundRobinBalancer{}
		default:
			service.LoadBalancer = &RoundRobinBalancer{}
		}

		// Initialize instances
		for _, instanceConfig := range serviceConfig.Instances {
			instance, err := NewInstance(instanceConfig.URL, instanceConfig.Weight)
			if err != nil {
				continue // Skip invalid instances
			}
			service.Instances = append(service.Instances, instance)
		}

		pool.services[name] = service
	}

	return pool
}

// NewInstance creates a new service instance
func NewInstance(targetURL string, weight int) (*Instance, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %s: %w", targetURL, err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	// Customize proxy behavior
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Add custom headers
		resp.Header.Set("X-Proxy-By", "Tidings-API-Gateway")
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"Service unavailable","message":"Upstream service is not responding"}`))
	}

	return &Instance{
		URL:       parsedURL,
		Weight:    weight,
		Health:    HealthStatusUnknown,
		Proxy:     proxy,
		LastCheck: time.Now(),
	}, nil
}

// GetService returns a service by name
func (p *Pool) GetService(name string) (*Service, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	service, exists := p.services[name]
	return service, exists
}

// ProxyRequest proxies a request to an upstream service
func (p *Pool) ProxyRequest(serviceName string, w http.ResponseWriter, r *http.Request) error {
	service, exists := p.GetService(serviceName)
	if !exists {
		return fmt.Errorf("service %s not found", serviceName)
	}

	// Get healthy instances
	healthyInstances := service.GetHealthyInstances()
	if len(healthyInstances) == 0 {
		return fmt.Errorf("no healthy instances available for service %s", serviceName)
	}

	// Select instance using load balancer
	instance := service.LoadBalancer.NextInstance(healthyInstances)
	if instance == nil {
		return fmt.Errorf("no instance selected for service %s", serviceName)
	}

	// Add service headers
	for key, value := range service.Config.Headers {
		r.Header.Set(key, value)
	}

	// Add proxy headers
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
	r.Header.Set("X-Forwarded-Host", r.Host)

	// Proxy the request
	instance.Proxy.ServeHTTP(w, r)
	return nil
}

// GetHealthyInstances returns all healthy instances
func (s *Service) GetHealthyInstances() []*Instance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var healthy []*Instance
	for _, instance := range s.Instances {
		if instance.IsHealthy() {
			healthy = append(healthy, instance)
		}
	}
	return healthy
}

// IsHealthy checks if the instance is healthy
func (i *Instance) IsHealthy() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.Health == HealthStatusHealthy
}

// SetHealth sets the health status of the instance
func (i *Instance) SetHealth(status HealthStatus) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Health = status
	i.LastCheck = time.Now()
}

// CheckHealth performs a health check on the instance
func (i *Instance) CheckHealth(healthPath string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
	}

	healthURL := i.URL.String() + healthPath
	resp, err := client.Get(healthURL)
	if err != nil {
		i.SetHealth(HealthStatusUnhealthy)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		i.SetHealth(HealthStatusHealthy)
		return nil
	}

	i.SetHealth(HealthStatusUnhealthy)
	return fmt.Errorf("health check failed with status %d", resp.StatusCode)
}

// Round Robin Load Balancer Implementation
func (rb *RoundRobinBalancer) NextInstance(instances []*Instance) *Instance {
	if len(instances) == 0 {
		return nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	instance := instances[rb.current%len(instances)]
	rb.current++
	return instance
}

func (rb *RoundRobinBalancer) Name() string {
	return "round_robin"
}

// Least Connections Load Balancer Implementation
func (lc *LeastConnectionsBalancer) NextInstance(instances []*Instance) *Instance {
	if len(instances) == 0 {
		return nil
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	var selected *Instance
	minConnections := int(^uint(0) >> 1) // Max int

	for _, instance := range instances {
		connections := lc.connections[instance.URL.String()]
		if connections < minConnections {
			minConnections = connections
			selected = instance
		}
	}

	if selected != nil {
		lc.connections[selected.URL.String()]++
	}

	return selected
}

func (lc *LeastConnectionsBalancer) Name() string {
	return "least_connections"
}

// ReleaseConnection decreases the connection count for an instance
func (lc *LeastConnectionsBalancer) ReleaseConnection(instanceURL string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if count, exists := lc.connections[instanceURL]; exists && count > 0 {
		lc.connections[instanceURL]--
	}
}

// Weighted Round Robin Load Balancer Implementation
func (wrr *WeightedRoundRobinBalancer) NextInstance(instances []*Instance) *Instance {
	if len(instances) == 0 {
		return nil
	}

	wrr.mu.Lock()
	defer wrr.mu.Unlock()

	// Build weighted list if not exists or changed
	if len(wrr.weights) != len(instances) {
		wrr.weights = make([]int, 0)
		for _, instance := range instances {
			for i := 0; i < instance.Weight; i++ {
				wrr.weights = append(wrr.weights, len(wrr.weights))
			}
		}
	}

	if len(wrr.weights) == 0 {
		return instances[0]
	}

	weightIndex := wrr.weights[wrr.current%len(wrr.weights)]
	wrr.current++

	if weightIndex < len(instances) {
		return instances[weightIndex]
	}

	return instances[0]
}

func (wrr *WeightedRoundRobinBalancer) Name() string {
	return "weighted_round_robin"
}

// GetStats returns statistics for the service
func (s *Service) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"name":              s.Name,
		"total_instances":   len(s.Instances),
		"healthy_instances": len(s.GetHealthyInstances()),
		"load_balancer":     s.LoadBalancer.Name(),
		"instances":         make([]map[string]interface{}, 0),
	}

	for _, instance := range s.Instances {
		instanceStats := map[string]interface{}{
			"url":        instance.URL.String(),
			"weight":     instance.Weight,
			"health":     string(instance.Health),
			"last_check": instance.LastCheck,
		}
		stats["instances"] = append(stats["instances"].([]map[string]interface{}), instanceStats)
	}

	return stats
}

// GetAllStats returns statistics for all services
func (p *Pool) GetAllStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := map[string]interface{}{
		"total_services": len(p.services),
		"services":       make(map[string]interface{}),
	}

	for name, service := range p.services {
		stats["services"].(map[string]interface{})[name] = service.GetStats()
	}

	return stats
}
