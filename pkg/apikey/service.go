package apikey

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Service manages API keys and their operations
type Service struct {
	apiKeys map[string]*APIKey // key -> APIKey
	userKeys map[string][]string // userID -> []keyIDs
	usage   map[string][]*APIKeyUsage // keyID -> usage records
	mu      sync.RWMutex
}

// NewService creates a new API key service
func NewService() *Service {
	service := &Service{
		apiKeys:  make(map[string]*APIKey),
		userKeys: make(map[string][]string),
		usage:    make(map[string][]*APIKeyUsage),
	}

	// Initialize with demo API keys
	service.initializeDemoKeys()

	return service
}

// initializeDemoKeys creates demo API keys for testing
func (s *Service) initializeDemoKeys() {
	// Demo admin API key
	adminKey, _ := GenerateAPIKey()
	adminKeyID, _ := GenerateAPIKeyID()
	adminAPIKey := &APIKey{
		ID:          adminKeyID,
		Key:         adminKey,
		Name:        "Admin API Key",
		Description: "Full administrative access for testing",
		UserID:      "admin-001",
		Scopes:      []string{"admin"},
		RateLimit:   PremiumRateLimit(),
		Metadata: map[string]string{
			"environment": "development",
			"team":        "platform",
		},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		IsActive:   true,
		UsageCount: 0,
	}
	s.apiKeys[adminKey] = adminAPIKey
	s.userKeys["admin-001"] = []string{adminKeyID}

	// Demo user API key
	userKey, _ := GenerateAPIKey()
	userKeyID, _ := GenerateAPIKeyID()
	userAPIKey := &APIKey{
		ID:          userKeyID,
		Key:         userKey,
		Name:        "User API Key",
		Description: "Standard user access for testing",
		UserID:      "user-001",
		Scopes:      []string{"read", "users:read", "orders:read"},
		RateLimit:   DefaultRateLimit(),
		Metadata: map[string]string{
			"environment": "development",
			"team":        "frontend",
		},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		IsActive:   true,
		UsageCount: 0,
	}
	s.apiKeys[userKey] = userAPIKey
	s.userKeys["user-001"] = []string{userKeyID}

	// Demo service API key with expiration
	serviceKey, _ := GenerateAPIKey()
	serviceKeyID, _ := GenerateAPIKeyID()
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days
	serviceAPIKey := &APIKey{
		ID:          serviceKeyID,
		Key:         serviceKey,
		Name:        "Service API Key",
		Description: "Service-to-service communication",
		UserID:      "service-001",
		Scopes:      []string{"read", "write", "users:read", "users:write", "orders:read", "orders:write"},
		RateLimit:   PremiumRateLimit(),
		Metadata: map[string]string{
			"environment": "development",
			"service":     "order-processor",
		},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		ExpiresAt:  &expiresAt,
		IsActive:   true,
		UsageCount: 0,
	}
	s.apiKeys[serviceKey] = serviceAPIKey
	s.userKeys["service-001"] = []string{serviceKeyID}
}

// CreateAPIKey creates a new API key
func (s *Service) CreateAPIKey(userID string, req *CreateAPIKeyRequest) (*APIKey, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate API key and ID
	key, err := GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	keyID, err := GenerateAPIKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key ID: %w", err)
	}

	// Set default rate limit if not provided
	rateLimit := req.RateLimit
	if rateLimit == nil {
		rateLimit = DefaultRateLimit()
	}

	// Create API key
	apiKey := &APIKey{
		ID:          keyID,
		Key:         key,
		Name:        req.Name,
		Description: req.Description,
		UserID:      userID,
		Scopes:      req.Scopes,
		RateLimit:   rateLimit,
		Metadata:    req.Metadata,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ExpiresAt:   req.ExpiresAt,
		IsActive:    true,
		UsageCount:  0,
	}

	// Store API key
	s.apiKeys[key] = apiKey

	// Add to user's keys
	if s.userKeys[userID] == nil {
		s.userKeys[userID] = make([]string, 0)
	}
	s.userKeys[userID] = append(s.userKeys[userID], keyID)

	return apiKey, nil
}

// GetAPIKey retrieves an API key by its key string
func (s *Service) GetAPIKey(key string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	apiKey, exists := s.apiKeys[key]
	if !exists {
		return nil, fmt.Errorf("API key not found")
	}

	// Return a copy to prevent external modification
	keyCopy := *apiKey
	return &keyCopy, nil
}

// GetAPIKeyByID retrieves an API key by its ID
func (s *Service) GetAPIKeyByID(keyID string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, apiKey := range s.apiKeys {
		if apiKey.ID == keyID {
			keyCopy := *apiKey
			return &keyCopy, nil
		}
	}

	return nil, fmt.Errorf("API key not found")
}

// ValidateAPIKey validates an API key and returns it if valid
func (s *Service) ValidateAPIKey(key string) (*APIKey, error) {
	apiKey, err := s.GetAPIKey(key)
	if err != nil {
		return nil, err
	}

	if !apiKey.IsValid() {
		if apiKey.IsExpired() {
			return nil, fmt.Errorf("API key has expired")
		}
		return nil, fmt.Errorf("API key is inactive")
	}

	return apiKey, nil
}

// ListAPIKeys returns a paginated list of API keys for a user
func (s *Service) ListAPIKeys(userID string, page, pageSize int) (*APIKeyListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyIDs, exists := s.userKeys[userID]
	if !exists {
		return &APIKeyListResponse{
			APIKeys:    []*APIKey{},
			Total:      0,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: 0,
		}, nil
	}

	// Get all API keys for the user
	var apiKeys []*APIKey
	for _, keyID := range keyIDs {
		for _, apiKey := range s.apiKeys {
			if apiKey.ID == keyID {
				keyCopy := *apiKey
				keyCopy.Key = "" // Don't expose the actual key in lists
				apiKeys = append(apiKeys, &keyCopy)
				break
			}
		}
	}

	// Sort by creation date (newest first)
	sort.Slice(apiKeys, func(i, j int) bool {
		return apiKeys[i].CreatedAt.After(apiKeys[j].CreatedAt)
	})

	total := len(apiKeys)
	totalPages := (total + pageSize - 1) / pageSize

	// Apply pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= total {
		apiKeys = []*APIKey{}
	} else {
		if end > total {
			end = total
		}
		apiKeys = apiKeys[start:end]
	}

	return &APIKeyListResponse{
		APIKeys:    apiKeys,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// UpdateAPIKey updates an existing API key
func (s *Service) UpdateAPIKey(keyID string, req *UpdateAPIKeyRequest) (*APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the API key
	var apiKey *APIKey
	for _, ak := range s.apiKeys {
		if ak.ID == keyID {
			apiKey = ak
			break
		}
	}

	if apiKey == nil {
		return nil, fmt.Errorf("API key not found")
	}

	// Update fields
	if req.Name != nil {
		apiKey.Name = *req.Name
	}
	if req.Description != nil {
		apiKey.Description = *req.Description
	}
	if req.Scopes != nil {
		apiKey.Scopes = req.Scopes
	}
	if req.RateLimit != nil {
		apiKey.RateLimit = req.RateLimit
	}
	if req.Metadata != nil {
		apiKey.Metadata = req.Metadata
	}
	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}
	if req.IsActive != nil {
		apiKey.IsActive = *req.IsActive
	}

	apiKey.UpdatedAt = time.Now()

	// Return a copy
	keyCopy := *apiKey
	return &keyCopy, nil
}

// DeleteAPIKey deletes an API key
func (s *Service) DeleteAPIKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find and remove the API key
	var keyToDelete string
	var userID string
	for key, apiKey := range s.apiKeys {
		if apiKey.ID == keyID {
			keyToDelete = key
			userID = apiKey.UserID
			break
		}
	}

	if keyToDelete == "" {
		return fmt.Errorf("API key not found")
	}

	// Remove from apiKeys map
	delete(s.apiKeys, keyToDelete)

	// Remove from user's keys
	if userKeys, exists := s.userKeys[userID]; exists {
		for i, id := range userKeys {
			if id == keyID {
				s.userKeys[userID] = append(userKeys[:i], userKeys[i+1:]...)
				break
			}
		}
	}

	// Remove usage data
	delete(s.usage, keyID)

	return nil
}

// RecordUsage records usage for an API key
func (s *Service) RecordUsage(key string, usage *APIKeyUsage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiKey, exists := s.apiKeys[key]
	if !exists {
		return fmt.Errorf("API key not found")
	}

	// Update API key usage
	apiKey.UpdateUsage()

	// Store usage record
	usage.APIKeyID = apiKey.ID
	usage.Timestamp = time.Now()

	if s.usage[apiKey.ID] == nil {
		s.usage[apiKey.ID] = make([]*APIKeyUsage, 0)
	}
	s.usage[apiKey.ID] = append(s.usage[apiKey.ID], usage)

	// Keep only last 1000 usage records per key
	if len(s.usage[apiKey.ID]) > 1000 {
		s.usage[apiKey.ID] = s.usage[apiKey.ID][len(s.usage[apiKey.ID])-1000:]
	}

	return nil
}

// GetAPIKeyStats returns usage statistics for an API key
func (s *Service) GetAPIKeyStats(keyID string) (*APIKeyStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	usageRecords, exists := s.usage[keyID]
	if !exists || len(usageRecords) == 0 {
		return &APIKeyStats{
			APIKeyID: keyID,
		}, nil
	}

	// Calculate statistics
	var totalRequests int64
	var successfulReqs int64
	var failedRequests int64
	var totalLatency int64
	endpointCount := make(map[string]int)
	
	now := time.Now()
	today := now.Truncate(24 * time.Hour)
	thisWeek := now.AddDate(0, 0, -7)

	var requestsToday int64
	var requestsThisWeek int64
	var lastUsed time.Time

	for _, usage := range usageRecords {
		totalRequests++
		totalLatency += usage.ResponseTime

		if usage.StatusCode >= 200 && usage.StatusCode < 400 {
			successfulReqs++
		} else {
			failedRequests++
		}

		endpointCount[usage.Endpoint]++

		if usage.Timestamp.After(today) {
			requestsToday++
		}
		if usage.Timestamp.After(thisWeek) {
			requestsThisWeek++
		}
		if usage.Timestamp.After(lastUsed) {
			lastUsed = usage.Timestamp
		}
	}

	// Calculate average latency
	var averageLatency float64
	if totalRequests > 0 {
		averageLatency = float64(totalLatency) / float64(totalRequests)
	}

	// Calculate error rate
	var errorRate float64
	if totalRequests > 0 {
		errorRate = (float64(failedRequests) / float64(totalRequests)) * 100
	}

	// Get top endpoints
	type endpointStat struct {
		endpoint string
		count    int
	}
	var endpoints []endpointStat
	for endpoint, count := range endpointCount {
		endpoints = append(endpoints, endpointStat{endpoint, count})
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].count > endpoints[j].count
	})

	var topEndpoints []string
	for i, ep := range endpoints {
		if i >= 5 { // Top 5 endpoints
			break
		}
		topEndpoints = append(topEndpoints, ep.endpoint)
	}

	return &APIKeyStats{
		APIKeyID:         keyID,
		TotalRequests:    totalRequests,
		SuccessfulReqs:   successfulReqs,
		FailedRequests:   failedRequests,
		AverageLatency:   averageLatency,
		LastUsed:         lastUsed,
		TopEndpoints:     topEndpoints,
		ErrorRate:        errorRate,
		RequestsToday:    requestsToday,
		RequestsThisWeek: requestsThisWeek,
	}, nil
}

// GetAllAPIKeys returns all API keys (admin only)
func (s *Service) GetAllAPIKeys() []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var apiKeys []*APIKey
	for _, apiKey := range s.apiKeys {
		keyCopy := *apiKey
		keyCopy.Key = "" // Don't expose actual keys
		apiKeys = append(apiKeys, &keyCopy)
	}

	return apiKeys
}

// SearchAPIKeys searches for API keys by name or description
func (s *Service) SearchAPIKeys(userID, query string) ([]*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyIDs, exists := s.userKeys[userID]
	if !exists {
		return []*APIKey{}, nil
	}

	var results []*APIKey
	query = strings.ToLower(query)

	for _, keyID := range keyIDs {
		for _, apiKey := range s.apiKeys {
			if apiKey.ID == keyID {
				if strings.Contains(strings.ToLower(apiKey.Name), query) ||
					strings.Contains(strings.ToLower(apiKey.Description), query) {
					keyCopy := *apiKey
					keyCopy.Key = "" // Don't expose the actual key
					results = append(results, &keyCopy)
				}
				break
			}
		}
	}

	return results, nil
}
