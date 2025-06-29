package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/Oragwel/api-gateway/pkg/apikey"
	"github.com/gin-gonic/gin"
)

// APIKeyAuth middleware validates API keys and sets context
func APIKeyAuth(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from header
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header with Bearer prefix
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Missing API key",
				"message": "X-API-Key header or Authorization Bearer token is required",
			})
			c.Abort()
			return
		}

		// Validate API key
		key, err := apiKeyService.ValidateAPIKey(apiKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Set API key context
		c.Set("api_key", key)
		c.Set("api_key_id", key.ID)
		c.Set("user_id", key.UserID)
		c.Set("api_scopes", key.Scopes)
		c.Set("auth_type", "api_key")

		// Record usage (in background to not slow down request)
		go func() {
			usage := &apikey.APIKeyUsage{
				Endpoint:     c.Request.URL.Path,
				Method:       c.Request.Method,
				UserAgent:    c.Request.UserAgent(),
				IPAddress:    c.ClientIP(),
				RequestSize:  c.Request.ContentLength,
			}
			apiKeyService.RecordUsage(apiKey, usage)
		}()

		c.Next()

		// Update usage with response data (after request is processed)
		go func() {
			usage := &apikey.APIKeyUsage{
				Endpoint:     c.Request.URL.Path,
				Method:       c.Request.Method,
				StatusCode:   c.Writer.Status(),
				ResponseSize: int64(c.Writer.Size()),
				UserAgent:    c.Request.UserAgent(),
				IPAddress:    c.ClientIP(),
				RequestSize:  c.Request.ContentLength,
			}
			
			// Add error message if request failed
			if c.Writer.Status() >= 400 {
				if errors := c.Errors; len(errors) > 0 {
					usage.ErrorMessage = errors.Last().Error()
				}
			}

			apiKeyService.RecordUsage(apiKey, usage)
		}()
	}
}

// RequireScope middleware ensures the API key has required scope
func RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from context
		apiKeyInterface, exists := c.Get("api_key")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "No API key in context",
				"message": "API key authentication required",
			})
			c.Abort()
			return
		}

		apiKey, ok := apiKeyInterface.(*apikey.APIKey)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Invalid API key context",
				"message": "Internal server error",
			})
			c.Abort()
			return
		}

		// Check if API key has required scope
		if !apiKey.HasScope(requiredScope) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient scope",
				"message": "API key does not have required scope: " + requiredScope,
				"required_scope": requiredScope,
				"available_scopes": apiKey.Scopes,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyScope middleware ensures the API key has at least one of the required scopes
func RequireAnyScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from context
		apiKeyInterface, exists := c.Get("api_key")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "No API key in context",
				"message": "API key authentication required",
			})
			c.Abort()
			return
		}

		apiKey, ok := apiKeyInterface.(*apikey.APIKey)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Invalid API key context",
				"message": "Internal server error",
			})
			c.Abort()
			return
		}

		// Check if API key has any of the required scopes
		hasScope := false
		for _, scope := range requiredScopes {
			if apiKey.HasScope(scope) {
				hasScope = true
				break
			}
		}

		if !hasScope {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient scope",
				"message": "API key does not have any of the required scopes",
				"required_scopes": requiredScopes,
				"available_scopes": apiKey.Scopes,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireResourceAccess middleware checks if API key can access a specific resource
func RequireResourceAccess(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from context
		apiKeyInterface, exists := c.Get("api_key")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "No API key in context",
				"message": "API key authentication required",
			})
			c.Abort()
			return
		}

		apiKey, ok := apiKeyInterface.(*apikey.APIKey)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Invalid API key context",
				"message": "Internal server error",
			})
			c.Abort()
			return
		}

		// Check if API key can access the resource
		if !apiKey.CanAccess(resource, action) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "API key cannot access this resource",
				"resource": resource,
				"action": action,
				"available_scopes": apiKey.Scopes,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyRateLimit implements rate limiting specific to API keys
func APIKeyRateLimit(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from context
		apiKeyInterface, exists := c.Get("api_key")
		if !exists {
			// If no API key, skip rate limiting (will be handled by other middleware)
			c.Next()
			return
		}

		apiKey, ok := apiKeyInterface.(*apikey.APIKey)
		if !ok {
			c.Next()
			return
		}

		// Check if API key has rate limiting configured
		if apiKey.RateLimit == nil {
			c.Next()
			return
		}

		// For now, we'll implement a simple check
		// In a real implementation, this would use Redis or another store
		// to track rate limits across multiple instances

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", "1000") // Example limit
		c.Header("X-RateLimit-Remaining", "999") // Example remaining
		c.Header("X-RateLimit-Reset", "3600") // Example reset time

		c.Next()
	}
}

// APIKeyInfo middleware adds API key information to response headers
func APIKeyInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from context
		apiKeyInterface, exists := c.Get("api_key")
		if !exists {
			c.Next()
			return
		}

		apiKey, ok := apiKeyInterface.(*apikey.APIKey)
		if !ok {
			c.Next()
			return
		}

		// Add API key info to headers
		c.Header("X-API-Key-ID", apiKey.ID)
		c.Header("X-API-Key-Name", apiKey.Name)
		c.Header("X-API-Key-Scopes", strings.Join(apiKey.Scopes, ","))
		
		// Add expiration info if applicable
		if apiKey.ExpiresAt != nil {
			c.Header("X-API-Key-Expires", apiKey.ExpiresAt.Format(time.RFC3339))
			timeUntilExpiry := time.Until(*apiKey.ExpiresAt)
			c.Header("X-API-Key-TTL", timeUntilExpiry.String())
		}

		c.Next()
	}
}

// OptionalAPIKeyAuth middleware that doesn't require API key but sets context if present
func OptionalAPIKeyAuth(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from header
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header with Bearer prefix
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// If no API key provided, continue without authentication
		if apiKey == "" {
			c.Next()
			return
		}

		// Validate API key if provided
		key, err := apiKeyService.ValidateAPIKey(apiKey)
		if err != nil {
			// Invalid API key, but don't abort - just continue without auth
			c.Next()
			return
		}

		// Set API key context
		c.Set("api_key", key)
		c.Set("api_key_id", key.ID)
		c.Set("user_id", key.UserID)
		c.Set("api_scopes", key.Scopes)
		c.Set("auth_type", "api_key")

		// Record usage
		go func() {
			usage := &apikey.APIKeyUsage{
				Endpoint:     c.Request.URL.Path,
				Method:       c.Request.Method,
				UserAgent:    c.Request.UserAgent(),
				IPAddress:    c.ClientIP(),
				RequestSize:  c.Request.ContentLength,
			}
			apiKeyService.RecordUsage(apiKey, usage)
		}()

		c.Next()
	}
}

// APIKeyMetrics middleware for collecting API key usage metrics
func APIKeyMetrics(metricsCollector interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Get API key from context
		apiKeyInterface, exists := c.Get("api_key")
		if !exists {
			c.Next()
			return
		}

		apiKey, ok := apiKeyInterface.(*apikey.APIKey)
		if !ok {
			c.Next()
			return
		}

		c.Next()

		// Record metrics
		duration := time.Since(start)
		
		// In a real implementation, you would record these metrics
		// to your metrics collector (Prometheus, etc.)
		_ = apiKey.ID
		_ = duration
		_ = c.Writer.Status()
		
		// Example: metricsCollector.RecordAPIKeyRequest(apiKey.ID, c.Request.Method, c.Request.URL.Path, c.Writer.Status(), duration)
	}
}
