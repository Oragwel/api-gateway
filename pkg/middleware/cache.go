package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Oragwel/api-gateway/pkg/cache"
	"github.com/gin-gonic/gin"
)

// CacheMiddleware provides HTTP response caching functionality
type CacheMiddleware struct {
	redis   *cache.RedisClient
	enabled bool
	ttl     time.Duration
}

// NewCacheMiddleware creates a new cache middleware
func NewCacheMiddleware(redis *cache.RedisClient, enabled bool, ttl time.Duration) *CacheMiddleware {
	return &CacheMiddleware{
		redis:   redis,
		enabled: enabled,
		ttl:     ttl,
	}
}

// CacheResponse represents a cached HTTP response
type CacheResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	Timestamp  time.Time           `json:"timestamp"`
}

// responseWriter wraps gin.ResponseWriter to capture response data
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

// Cache middleware function
func (cm *CacheMiddleware) Cache() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip caching if disabled
		if !cm.enabled || cm.redis == nil {
			c.Next()
			return
		}

		// Only cache GET requests
		if c.Request.Method != "GET" {
			c.Next()
			return
		}

		// Skip caching for certain paths
		if cm.shouldSkipCache(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Generate cache key
		cacheKey := cm.generateCacheKey(c)

		// Try to get cached response
		var cachedResponse CacheResponse
		err := cm.redis.Get(cacheKey, &cachedResponse)
		if err == nil {
			// Cache hit - return cached response
			cm.serveCachedResponse(c, &cachedResponse)
			return
		}

		// Cache miss - proceed with request and cache response
		cm.cacheResponse(c, cacheKey)
	}
}

// generateCacheKey creates a unique cache key for the request
func (cm *CacheMiddleware) generateCacheKey(c *gin.Context) string {
	// Include method, path, query parameters, and relevant headers
	key := fmt.Sprintf("cache:%s:%s", c.Request.Method, c.Request.URL.Path)

	// Add query parameters
	if c.Request.URL.RawQuery != "" {
		key += ":" + c.Request.URL.RawQuery
	}

	// Add user context for personalized caching
	if userID, exists := c.Get("user_id"); exists {
		key += ":user:" + fmt.Sprintf("%v", userID)
	}

	// Add API version if present
	if version := c.GetHeader("API-Version"); version != "" {
		key += ":v:" + version
	}

	return key
}

// shouldSkipCache determines if a path should be excluded from caching
func (cm *CacheMiddleware) shouldSkipCache(path string) bool {
	skipPaths := []string{
		"/health",
		"/metrics",
		"/auth/",
		"/admin/",
		"/ws/",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

// serveCachedResponse serves a response from cache
func (cm *CacheMiddleware) serveCachedResponse(c *gin.Context, cachedResponse *CacheResponse) {
	// Set cached headers
	for key, values := range cachedResponse.Headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// Add cache headers
	c.Header("X-Cache", "HIT")
	c.Header("X-Cache-Timestamp", cachedResponse.Timestamp.Format(time.RFC3339))
	c.Header("X-Cache-Age", strconv.Itoa(int(time.Since(cachedResponse.Timestamp).Seconds())))

	// Set status and body
	c.Data(cachedResponse.StatusCode, c.GetHeader("Content-Type"), []byte(cachedResponse.Body))
	c.Abort()
}

// cacheResponse captures and caches the response
func (cm *CacheMiddleware) cacheResponse(c *gin.Context, cacheKey string) {
	// Create custom response writer to capture response
	writer := &responseWriter{
		ResponseWriter: c.Writer,
		body:           bytes.NewBuffer([]byte{}),
	}
	c.Writer = writer

	// Process request
	c.Next()

	// Only cache successful responses
	if cm.shouldCacheResponse(writer.Status(), c.Request.Method) {
		// Capture response data
		cachedResponse := CacheResponse{
			StatusCode: writer.Status(),
			Headers:    make(map[string][]string),
			Body:       writer.body.String(),
			Timestamp:  time.Now(),
		}

		// Copy response headers (excluding some)
		for key, values := range writer.Header() {
			if cm.shouldCacheHeader(key) {
				cachedResponse.Headers[key] = values
			}
		}

		// Add cache headers to original response
		c.Header("X-Cache", "MISS")
		c.Header("X-Cache-Stored", "true")

		// Store in cache
		go func() {
			err := cm.redis.Set(cacheKey, cachedResponse, cm.ttl)
			if err != nil {
				// Log error but don't fail the request
				fmt.Printf("Failed to cache response: %v\n", err)
			}
		}()
	} else {
		c.Header("X-Cache", "SKIP")
	}
}

// shouldCacheResponse determines if a response should be cached
func (cm *CacheMiddleware) shouldCacheResponse(statusCode int, method string) bool {
	// Only cache successful GET requests
	return method == "GET" && statusCode >= 200 && statusCode < 300
}

// shouldCacheHeader determines if a header should be cached
func (cm *CacheMiddleware) shouldCacheHeader(headerKey string) bool {
	skipHeaders := []string{
		"Set-Cookie",
		"Authorization",
		"X-Request-ID",
		"Date",
		"Server",
	}

	headerKeyLower := strings.ToLower(headerKey)
	for _, skipHeader := range skipHeaders {
		if strings.ToLower(skipHeader) == headerKeyLower {
			return false
		}
	}

	return true
}

// InvalidateCache removes cached responses matching a pattern
func (cm *CacheMiddleware) InvalidateCache(pattern string) error {
	if !cm.enabled || cm.redis == nil {
		return nil
	}

	return cm.redis.InvalidatePattern(fmt.Sprintf("cache:%s", pattern))
}

// InvalidateCacheForPath removes all cached responses for a specific path
func (cm *CacheMiddleware) InvalidateCacheForPath(path string) error {
	pattern := fmt.Sprintf("*:%s:*", path)
	return cm.InvalidateCache(pattern)
}

// InvalidateCacheForUser removes all cached responses for a specific user
func (cm *CacheMiddleware) InvalidateCacheForUser(userID string) error {
	pattern := fmt.Sprintf("*:user:%s:*", userID)
	return cm.InvalidateCache(pattern)
}

// GetCacheStats returns cache statistics
func (cm *CacheMiddleware) GetCacheStats() map[string]interface{} {
	if !cm.enabled || cm.redis == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	stats := cm.redis.GetStats()
	stats["enabled"] = true
	stats["ttl_seconds"] = int(cm.ttl.Seconds())

	return stats
}

// WarmupCache pre-loads cache with common requests
func (cm *CacheMiddleware) WarmupCache(urls []string) error {
	if !cm.enabled || cm.redis == nil {
		return fmt.Errorf("cache is not enabled")
	}

	for _, url := range urls {
		// Create a mock request to generate cache key
		_, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// This would typically involve making actual requests
		// For now, we'll just log the warmup attempt
		fmt.Printf("Cache warmup for URL: %s\n", url)
	}

	return nil
}

// CacheHealthCheck verifies cache connectivity
func (cm *CacheMiddleware) CacheHealthCheck() error {
	if !cm.enabled || cm.redis == nil {
		return fmt.Errorf("cache is disabled")
	}

	// Test Redis connectivity with a simple operation
	testKey := "health_check_" + strconv.FormatInt(time.Now().Unix(), 10)
	err := cm.redis.Set(testKey, "ok", time.Minute)
	if err != nil {
		return fmt.Errorf("cache write failed: %w", err)
	}

	var result string
	err = cm.redis.Get(testKey, &result)
	if err != nil {
		return fmt.Errorf("cache read failed: %w", err)
	}

	// Clean up test key
	cm.redis.Delete(testKey)

	if result != "ok" {
		return fmt.Errorf("cache data integrity check failed")
	}

	return nil
}
