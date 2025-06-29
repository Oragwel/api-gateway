package handlers

import (
	"net/http"
	"strconv"

	"github.com/Oragwel/api-gateway/pkg/apikey"
	"github.com/gin-gonic/gin"
)

// CreateAPIKey creates a new API key
func CreateAPIKey(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req apikey.CreateAPIKeyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Get user ID from context (set by auth middleware)
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Invalid user ID",
				"message": "User ID is not a string",
			})
			return
		}

		// Create API key
		apiKey, err := apiKeyService.CreateAPIKey(userIDStr, &req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Failed to create API key",
				"message": err.Error(),
			})
			return
		}

		// Return API key with the actual key (only time it's exposed)
		response := &apikey.APIKeyResponse{
			APIKey: apiKey,
			Key:    apiKey.Key, // Include the actual key in response
		}
		
		// Remove key from the embedded APIKey to avoid duplication
		response.APIKey.Key = ""

		c.JSON(http.StatusCreated, gin.H{
			"message": "API key created successfully",
			"data":    response,
		})
	}
}

// GetAPIKey retrieves an API key by ID
func GetAPIKey(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")
		if keyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing API key ID",
				"message": "API key ID is required",
			})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		// Get API key
		apiKey, err := apiKeyService.GetAPIKeyByID(keyID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "API key not found",
				"message": err.Error(),
			})
			return
		}

		// Check if user owns this API key (unless admin)
		isAdmin, _ := c.Get("is_admin")
		if !isAdmin.(bool) && apiKey.UserID != userID.(string) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "You can only access your own API keys",
			})
			return
		}

		// Don't expose the actual key
		apiKey.Key = ""

		c.JSON(http.StatusOK, gin.H{
			"data": apiKey,
		})
	}
}

// ListAPIKeys lists API keys for the authenticated user
func ListAPIKeys(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get pagination parameters
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
		
		if page < 1 {
			page = 1
		}
		if pageSize < 1 || pageSize > 100 {
			pageSize = 10
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		userIDStr := userID.(string)

		// List API keys
		response, err := apiKeyService.ListAPIKeys(userIDStr, page, pageSize)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to list API keys",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": response,
		})
	}
}

// UpdateAPIKey updates an existing API key
func UpdateAPIKey(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")
		if keyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing API key ID",
				"message": "API key ID is required",
			})
			return
		}

		var req apikey.UpdateAPIKeyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		// Check if user owns this API key (unless admin)
		existingKey, err := apiKeyService.GetAPIKeyByID(keyID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "API key not found",
				"message": err.Error(),
			})
			return
		}

		isAdmin, _ := c.Get("is_admin")
		if !isAdmin.(bool) && existingKey.UserID != userID.(string) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "You can only update your own API keys",
			})
			return
		}

		// Update API key
		updatedKey, err := apiKeyService.UpdateAPIKey(keyID, &req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Failed to update API key",
				"message": err.Error(),
			})
			return
		}

		// Don't expose the actual key
		updatedKey.Key = ""

		c.JSON(http.StatusOK, gin.H{
			"message": "API key updated successfully",
			"data":    updatedKey,
		})
	}
}

// DeleteAPIKey deletes an API key
func DeleteAPIKey(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")
		if keyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing API key ID",
				"message": "API key ID is required",
			})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		// Check if user owns this API key (unless admin)
		existingKey, err := apiKeyService.GetAPIKeyByID(keyID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "API key not found",
				"message": err.Error(),
			})
			return
		}

		isAdmin, _ := c.Get("is_admin")
		if !isAdmin.(bool) && existingKey.UserID != userID.(string) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "You can only delete your own API keys",
			})
			return
		}

		// Delete API key
		err = apiKeyService.DeleteAPIKey(keyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to delete API key",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "API key deleted successfully",
		})
	}
}

// GetAPIKeyStats returns usage statistics for an API key
func GetAPIKeyStats(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.Param("id")
		if keyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing API key ID",
				"message": "API key ID is required",
			})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		// Check if user owns this API key (unless admin)
		existingKey, err := apiKeyService.GetAPIKeyByID(keyID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "API key not found",
				"message": err.Error(),
			})
			return
		}

		isAdmin, _ := c.Get("is_admin")
		if !isAdmin.(bool) && existingKey.UserID != userID.(string) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "You can only view stats for your own API keys",
			})
			return
		}

		// Get API key stats
		stats, err := apiKeyService.GetAPIKeyStats(keyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to get API key stats",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": stats,
		})
	}
}

// SearchAPIKeys searches for API keys by name or description
func SearchAPIKeys(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Query("q")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing search query",
				"message": "Query parameter 'q' is required",
			})
			return
		}

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "User not authenticated",
				"message": "User ID not found in context",
			})
			return
		}

		userIDStr := userID.(string)

		// Search API keys
		results, err := apiKeyService.SearchAPIKeys(userIDStr, query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Search failed",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"query":   query,
				"results": results,
				"count":   len(results),
			},
		})
	}
}

// GetAvailableScopes returns the list of available API key scopes
func GetAvailableScopes() gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes := apikey.DefaultScopes()
		
		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"scopes": scopes,
				"count":  len(scopes),
			},
		})
	}
}

// ValidateAPIKeyEndpoint validates an API key (for testing purposes)
func ValidateAPIKeyEndpoint(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKeyStr := c.GetHeader("X-API-Key")
		if apiKeyStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing API key",
				"message": "X-API-Key header is required",
			})
			return
		}

		// Validate API key
		apiKey, err := apiKeyService.ValidateAPIKey(apiKeyStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": err.Error(),
				"valid":   false,
			})
			return
		}

		// Don't expose the actual key
		apiKey.Key = ""

		c.JSON(http.StatusOK, gin.H{
			"valid":   true,
			"message": "API key is valid",
			"data":    apiKey,
		})
	}
}

// GetAllAPIKeys returns all API keys (admin only)
func GetAllAPIKeys(apiKeyService *apikey.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This endpoint should be protected by admin middleware
		apiKeys := apiKeyService.GetAllAPIKeys()

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"api_keys": apiKeys,
				"count":    len(apiKeys),
			},
		})
	}
}
