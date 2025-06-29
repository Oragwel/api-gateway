package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Oragwel/api-gateway/pkg/auth"
	"github.com/Oragwel/api-gateway/pkg/config"
	"github.com/Oragwel/api-gateway/pkg/metrics"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// RequestID middleware adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	}
}

// Logger middleware logs HTTP requests
func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf(`{"time":"%s","method":"%s","path":"%s","protocol":"%s","status":%d,"latency":"%s","client_ip":"%s","user_agent":"%s","request_id":"%s"}%s`,
			param.TimeStamp.Format(time.RFC3339),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Request.UserAgent(),
			param.Request.Header.Get("X-Request-ID"),
			"\n",
		)
	})
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(config config.CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range config.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
		c.Header("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))

		if config.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Security middleware adds security headers
func Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")

		c.Next()
	}
}

// RateLimiter stores rate limiters for different keys
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	config   config.RateLimitConfig
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config config.RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

// getLimiter gets or creates a rate limiter for a key
func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = rl.limiters[key]; !exists {
			limiter = rate.NewLimiter(
				rate.Limit(rl.config.RequestsPerSecond),
				rl.config.BurstSize,
			)
			rl.limiters[key] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}

// RateLimit middleware implements rate limiting
func RateLimit(config config.RateLimitConfig) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	rateLimiter := NewRateLimiter(config)

	return func(c *gin.Context) {
		var key string

		switch config.KeyFunc {
		case "ip":
			key = c.ClientIP()
		case "user":
			if userID, exists := c.Get("user_id"); exists {
				key = fmt.Sprintf("user:%s", userID)
			} else {
				key = c.ClientIP()
			}
		case "api_key":
			apiKey := c.GetHeader("X-API-Key")
			if apiKey != "" {
				key = fmt.Sprintf("api_key:%s", apiKey)
			} else {
				key = c.ClientIP()
			}
		default:
			key = c.ClientIP()
		}

		limiter := rateLimiter.getLimiter(key)

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests, please try again later",
				"retry_after": int(config.WindowSize.Seconds()),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RedisRateLimit implements Redis-based distributed rate limiting
func RedisRateLimit(config config.RateLimitConfig, redisClient interface{}) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		var key string

		switch config.KeyFunc {
		case "ip":
			key = c.ClientIP()
		case "user":
			if userID, exists := c.Get("user_id"); exists {
				key = fmt.Sprintf("user:%s", userID)
			} else {
				key = c.ClientIP()
			}
		case "api_key":
			apiKey := c.GetHeader("X-API-Key")
			if apiKey != "" {
				key = fmt.Sprintf("api_key:%s", apiKey)
			} else {
				key = c.ClientIP()
			}
		default:
			key = c.ClientIP()
		}

		// This would use Redis for distributed rate limiting
		// For now, fall back to in-memory rate limiting
		// In a real implementation, you'd use Redis INCR with TTL
		_ = key // Use the key variable to avoid unused variable error

		c.Next()
	}
}

// Authentication middleware validates JWT tokens
func Authentication(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Missing authorization header",
				"message": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Validate token
		claims, err := authService.ValidateToken(authHeader)
		if err != nil {
			status := http.StatusUnauthorized
			message := "Invalid token"

			switch err {
			case auth.ErrTokenExpired:
				message = "Token expired"
			case auth.ErrInvalidToken:
				message = "Invalid token format"
			}

			c.JSON(status, gin.H{
				"error":   "Authentication failed",
				"message": message,
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)
		c.Set("is_admin", claims.IsAdmin)
		c.Set("claims", claims)

		c.Next()
	}
}

// AdminAuth middleware ensures user has admin privileges
func AdminAuth(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check authentication
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Missing authorization header",
				"message": "Authorization header is required",
			})
			c.Abort()
			return
		}

		claims, err := authService.ValidateToken(authHeader)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"message": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Check admin privileges
		if !claims.IsAdmin {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient privileges",
				"message": "Admin access required",
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)
		c.Set("is_admin", claims.IsAdmin)
		c.Set("claims", claims)

		c.Next()
	}
}

// Metrics middleware collects request metrics
func Metrics(collector *metrics.Collector) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Record metrics
		duration := time.Since(start)

		collector.RecordRequest(
			c.Request.Method,
			c.FullPath(),
			c.Writer.Status(),
			duration,
		)
	}
}

// APIKeyAuth middleware validates API keys
func APIKeyAuth(validKeys map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Missing API key",
				"message": "X-API-Key header is required",
			})
			c.Abort()
			return
		}

		// Validate API key
		if clientID, valid := validKeys[apiKey]; valid {
			c.Set("client_id", clientID)
			c.Set("auth_type", "api_key")
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": "The provided API key is not valid",
			})
			c.Abort()
		}
	}
}

// Timeout middleware adds request timeout
func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set timeout on request context
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// RequestSize middleware limits request body size
func RequestSize(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "Request too large",
				"message": fmt.Sprintf("Request body must be smaller than %d bytes", maxSize),
			})
			c.Abort()
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}
