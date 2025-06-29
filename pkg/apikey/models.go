package apikey

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// APIKey represents an API key in the system
type APIKey struct {
	ID          string            `json:"id"`
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	UserID      string            `json:"user_id"`
	Scopes      []string          `json:"scopes"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	IsActive    bool              `json:"is_active"`
	UsageCount  int64             `json:"usage_count"`
}

// RateLimit defines rate limiting rules for an API key
type RateLimit struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	RequestsPerMinute int           `json:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour"`
	RequestsPerDay    int           `json:"requests_per_day"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// APIKeyUsage tracks usage statistics for an API key
type APIKeyUsage struct {
	APIKeyID      string    `json:"api_key_id"`
	Timestamp     time.Time `json:"timestamp"`
	Endpoint      string    `json:"endpoint"`
	Method        string    `json:"method"`
	StatusCode    int       `json:"status_code"`
	ResponseTime  int64     `json:"response_time_ms"`
	RequestSize   int64     `json:"request_size_bytes"`
	ResponseSize  int64     `json:"response_size_bytes"`
	UserAgent     string    `json:"user_agent"`
	IPAddress     string    `json:"ip_address"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

// CreateAPIKeyRequest represents a request to create a new API key
type CreateAPIKeyRequest struct {
	Name        string            `json:"name" binding:"required"`
	Description string            `json:"description"`
	Scopes      []string          `json:"scopes"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// UpdateAPIKeyRequest represents a request to update an API key
type UpdateAPIKeyRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	IsActive    *bool             `json:"is_active,omitempty"`
}

// APIKeyResponse represents the response when creating/retrieving an API key
type APIKeyResponse struct {
	*APIKey
	Key string `json:"key,omitempty"` // Only included when creating
}

// APIKeyListResponse represents a paginated list of API keys
type APIKeyListResponse struct {
	APIKeys    []*APIKey `json:"api_keys"`
	Total      int       `json:"total"`
	Page       int       `json:"page"`
	PageSize   int       `json:"page_size"`
	TotalPages int       `json:"total_pages"`
}

// APIKeyStats represents usage statistics for an API key
type APIKeyStats struct {
	APIKeyID         string    `json:"api_key_id"`
	TotalRequests    int64     `json:"total_requests"`
	SuccessfulReqs   int64     `json:"successful_requests"`
	FailedRequests   int64     `json:"failed_requests"`
	AverageLatency   float64   `json:"average_latency_ms"`
	LastUsed         time.Time `json:"last_used"`
	TopEndpoints     []string  `json:"top_endpoints"`
	ErrorRate        float64   `json:"error_rate_percent"`
	RequestsToday    int64     `json:"requests_today"`
	RequestsThisWeek int64     `json:"requests_this_week"`
}

// Scope represents an API scope/permission
type Scope struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// DefaultScopes returns the default available scopes
func DefaultScopes() []Scope {
	return []Scope{
		{Name: "read", Description: "Read access to resources", Resource: "*", Action: "GET"},
		{Name: "write", Description: "Write access to resources", Resource: "*", Action: "POST,PUT,PATCH"},
		{Name: "delete", Description: "Delete access to resources", Resource: "*", Action: "DELETE"},
		{Name: "admin", Description: "Full administrative access", Resource: "*", Action: "*"},
		{Name: "users:read", Description: "Read user information", Resource: "users", Action: "GET"},
		{Name: "users:write", Description: "Create and update users", Resource: "users", Action: "POST,PUT,PATCH"},
		{Name: "orders:read", Description: "Read order information", Resource: "orders", Action: "GET"},
		{Name: "orders:write", Description: "Create and update orders", Resource: "orders", Action: "POST,PUT,PATCH"},
		{Name: "metrics:read", Description: "Read metrics and analytics", Resource: "metrics", Action: "GET"},
	}
}

// GenerateAPIKey generates a new API key string
func GenerateAPIKey() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex string and add prefix
	key := "gw_" + hex.EncodeToString(bytes)
	return key, nil
}

// GenerateAPIKeyID generates a unique ID for an API key
func GenerateAPIKeyID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return "ak_" + hex.EncodeToString(bytes), nil
}

// IsExpired checks if the API key has expired
func (ak *APIKey) IsExpired() bool {
	if ak.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ak.ExpiresAt)
}

// IsValid checks if the API key is valid for use
func (ak *APIKey) IsValid() bool {
	return ak.IsActive && !ak.IsExpired()
}

// HasScope checks if the API key has a specific scope
func (ak *APIKey) HasScope(scope string) bool {
	for _, s := range ak.Scopes {
		if s == scope || s == "admin" {
			return true
		}
	}
	return false
}

// CanAccess checks if the API key can access a resource with a specific action
func (ak *APIKey) CanAccess(resource, action string) bool {
	// Admin scope allows everything
	if ak.HasScope("admin") {
		return true
	}

	// Check specific resource scopes
	resourceScope := resource + ":" + action
	if ak.HasScope(resourceScope) {
		return true
	}

	// Check general action scopes
	switch action {
	case "GET":
		return ak.HasScope("read")
	case "POST", "PUT", "PATCH":
		return ak.HasScope("write")
	case "DELETE":
		return ak.HasScope("delete")
	}

	return false
}

// UpdateUsage updates the usage statistics for the API key
func (ak *APIKey) UpdateUsage() {
	now := time.Now()
	ak.LastUsedAt = &now
	ak.UsageCount++
	ak.UpdatedAt = now
}

// GetRateLimitForPeriod returns the rate limit for a specific period
func (rl *RateLimit) GetRateLimitForPeriod(period string) int {
	switch period {
	case "second":
		return rl.RequestsPerSecond
	case "minute":
		return rl.RequestsPerMinute
	case "hour":
		return rl.RequestsPerHour
	case "day":
		return rl.RequestsPerDay
	default:
		return rl.RequestsPerSecond
	}
}

// DefaultRateLimit returns a default rate limit configuration
func DefaultRateLimit() *RateLimit {
	return &RateLimit{
		RequestsPerSecond: 10,
		RequestsPerMinute: 600,
		RequestsPerHour:   36000,
		RequestsPerDay:    864000,
		BurstSize:         20,
		WindowSize:        time.Minute,
	}
}

// PremiumRateLimit returns a premium rate limit configuration
func PremiumRateLimit() *RateLimit {
	return &RateLimit{
		RequestsPerSecond: 100,
		RequestsPerMinute: 6000,
		RequestsPerHour:   360000,
		RequestsPerDay:    8640000,
		BurstSize:         200,
		WindowSize:        time.Minute,
	}
}

// ValidateAPIKeyRequest validates a create API key request
func (req *CreateAPIKeyRequest) Validate() error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	if len(req.Name) > 100 {
		return fmt.Errorf("name must be less than 100 characters")
	}

	if len(req.Description) > 500 {
		return fmt.Errorf("description must be less than 500 characters")
	}

	// Validate scopes
	validScopes := make(map[string]bool)
	for _, scope := range DefaultScopes() {
		validScopes[scope.Name] = true
	}

	for _, scope := range req.Scopes {
		if !validScopes[scope] {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}

	// Validate expiration date
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration date must be in the future")
	}

	return nil
}
