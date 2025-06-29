package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/Oragwel/api-gateway/pkg/auth"
	"github.com/Oragwel/api-gateway/pkg/config"
	"github.com/Oragwel/api-gateway/pkg/health"
	"github.com/Oragwel/api-gateway/pkg/metrics"
	"github.com/Oragwel/api-gateway/pkg/proxy"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// HealthCheck returns the health status of the gateway
func HealthCheck(healthChecker *health.Checker) gin.HandlerFunc {
	return func(c *gin.Context) {
		report := healthChecker.GetReport()

		statusCode := http.StatusOK
		if report.Status == health.StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		} else if report.Status == health.StatusDegraded {
			statusCode = http.StatusPartialContent
		}

		c.JSON(statusCode, report)
	}
}

// ReadinessCheck returns whether the gateway is ready to serve requests
func ReadinessCheck(healthChecker *health.Checker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if healthChecker.IsReady() {
			c.JSON(http.StatusOK, gin.H{
				"status":    "ready",
				"timestamp": time.Now(),
				"message":   "Gateway is ready to serve requests",
			})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":    "not_ready",
				"timestamp": time.Now(),
				"message":   "Gateway is not ready to serve requests",
			})
		}
	}
}

// LivenessCheck returns whether the gateway is alive
func LivenessCheck(healthChecker *health.Checker) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "alive",
			"timestamp": time.Now(),
			"message":   "Gateway is alive",
			"uptime":    time.Since(time.Now().Add(-time.Hour)).String(), // Placeholder
		})
	}
}

// Login handles user authentication
func Login(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req auth.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		tokens, err := authService.Login(req.Email, req.Password)
		if err != nil {
			status := http.StatusUnauthorized
			message := "Invalid credentials"

			if err == auth.ErrUserNotFound {
				message = "User not found"
			}

			c.JSON(status, gin.H{
				"error":   "Authentication failed",
				"message": message,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"data":    tokens,
		})
	}
}

// RefreshToken handles token refresh
func RefreshToken(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req auth.RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		tokens, err := authService.RefreshToken(req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Token refresh failed",
				"message": "Invalid or expired refresh token",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Token refreshed successfully",
			"data":    tokens,
		})
	}
}

// Logout handles user logout
func Logout(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req auth.RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		err := authService.RevokeToken(req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Logout failed",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Logout successful",
		})
	}
}

// ValidateToken validates a JWT token
func ValidateToken(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing authorization header",
				"message": "Authorization header is required",
			})
			return
		}

		claims, err := authService.ValidateToken(authHeader)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid token",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"valid": true,
			"data":  claims,
		})
	}
}

// ProxyRequest handles proxying requests to upstream services
func ProxyRequest(proxyPool *proxy.Pool, version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract service name from path
		path := c.Param("path")
		serviceName := extractServiceName(path, version)

		if serviceName == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request path",
				"message": "Unable to determine target service",
			})
			return
		}

		// Proxy the request
		err := proxyPool.ProxyRequest(serviceName, c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{
				"error":   "Proxy error",
				"message": err.Error(),
			})
			return
		}
	}
}

// extractServiceName extracts service name from the request path
func extractServiceName(path, version string) string {
	// Simple path-based routing
	// In a real implementation, you'd have more sophisticated routing logic

	if path == "" {
		return ""
	}

	// Remove leading slash
	if path[0] == '/' {
		path = path[1:]
	}

	// Extract first path segment as service name
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return ""
}

// GatewayStats returns gateway statistics
func GatewayStats(metricsCollector *metrics.Collector) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := metricsCollector.GetStats()
		summary := metricsCollector.GetSummary()

		c.JSON(http.StatusOK, gin.H{
			"gateway_stats": stats,
			"summary":       summary,
			"timestamp":     time.Now(),
		})
	}
}

// GetConfig returns the current gateway configuration (admin only)
func GetConfig(config *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Return sanitized config (without secrets)
		sanitizedConfig := map[string]interface{}{
			"server": map[string]interface{}{
				"port":          config.Server.Port,
				"host":          config.Server.Host,
				"mode":          config.Server.Mode,
				"read_timeout":  config.Server.ReadTimeout,
				"write_timeout": config.Server.WriteTimeout,
				"idle_timeout":  config.Server.IdleTimeout,
			},
			"rate_limit": config.RateLimit,
			"cors":       config.CORS,
			"health":     config.Health,
			"logging":    config.Logging,
			"metrics":    config.Metrics,
			"upstream": map[string]interface{}{
				"services_count": len(config.Upstream.Services),
				"services":       getServiceNames(config.Upstream.Services),
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"config":    sanitizedConfig,
			"timestamp": time.Now(),
		})
	}
}

// getServiceNames returns a list of service names
func getServiceNames(services map[string]config.ServiceConfig) []string {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	return names
}

// ReloadConfig reloads the gateway configuration (admin only)
func ReloadConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		// In a real implementation, you'd reload the configuration
		// For now, just return a success message
		c.JSON(http.StatusOK, gin.H{
			"message":   "Configuration reload initiated",
			"timestamp": time.Now(),
			"note":      "This is a placeholder implementation",
		})
	}
}

// UpstreamStatus returns the status of upstream services
func UpstreamStatus(proxyPool *proxy.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := proxyPool.GetAllStats()

		c.JSON(http.StatusOK, gin.H{
			"upstream_status": stats,
			"timestamp":       time.Now(),
		})
	}
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// WebSocketProxy handles WebSocket connections
func WebSocketProxy(proxyPool *proxy.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract service name from path
		path := c.Param("path")
		serviceName := extractServiceName(path, "ws")

		if serviceName == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid WebSocket path",
				"message": "Unable to determine target service",
			})
			return
		}

		// Upgrade connection to WebSocket
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "WebSocket upgrade failed",
				"message": err.Error(),
			})
			return
		}
		defer conn.Close()

		// Handle WebSocket proxy logic
		// This is a simplified implementation
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":   "WebSocket proxy not implemented",
			"message": "WebSocket proxying is not yet implemented",
		})
	}
}

// APIDocumentation serves API documentation
func APIDocumentation() gin.HandlerFunc {
	return func(c *gin.Context) {
		docs := map[string]interface{}{
			"title":       "Tidings Technologies API Gateway",
			"version":     "1.0.0",
			"description": "Professional API Gateway with authentication, rate limiting, and load balancing",
			"endpoints": map[string]interface{}{
				"health": map[string]interface{}{
					"GET /health":       "Gateway health status",
					"GET /health/ready": "Readiness check",
					"GET /health/live":  "Liveness check",
				},
				"auth": map[string]interface{}{
					"POST /auth/login":   "User login",
					"POST /auth/refresh": "Refresh token",
					"POST /auth/logout":  "User logout",
					"GET /auth/validate": "Validate token",
				},
				"api": map[string]interface{}{
					"ANY /api/v1/*": "Proxy to v1 services",
					"ANY /api/v2/*": "Proxy to v2 services",
				},
				"admin": map[string]interface{}{
					"GET /admin/stats":    "Gateway statistics",
					"GET /admin/config":   "Gateway configuration",
					"POST /admin/reload":  "Reload configuration",
					"GET /admin/upstream": "Upstream service status",
				},
				"metrics": map[string]interface{}{
					"GET /metrics": "Prometheus metrics",
				},
				"websocket": map[string]interface{}{
					"GET /ws/*": "WebSocket proxy",
				},
			},
			"authentication": map[string]interface{}{
				"type":   "Bearer Token (JWT)",
				"header": "Authorization: Bearer <token>",
			},
			"rate_limiting": map[string]interface{}{
				"enabled":     true,
				"default_rps": 100,
				"burst_size":  200,
			},
		}

		c.HTML(http.StatusOK, "docs.html", gin.H{
			"docs": docs,
		})
	}
}
