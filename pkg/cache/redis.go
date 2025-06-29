package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisClient wraps the Redis client with caching functionality
type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

// CacheConfig holds Redis configuration
type CacheConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	TTL      time.Duration
}

// NewRedisClient creates a new Redis client for caching
func NewRedisClient(config CacheConfig) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	ctx := context.Background()
	
	// Test connection
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClient{
		client: rdb,
		ctx:    ctx,
	}, nil
}

// Set stores a value in Redis with TTL
func (r *RedisClient) Set(key string, value interface{}, ttl time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	err = r.client.Set(r.ctx, key, jsonData, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}

// Get retrieves a value from Redis
func (r *RedisClient) Get(key string, dest interface{}) error {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("cache miss: key %s not found", key)
		}
		return fmt.Errorf("failed to get cache: %w", err)
	}

	err = json.Unmarshal([]byte(val), dest)
	if err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

// Delete removes a key from Redis
func (r *RedisClient) Delete(key string) error {
	err := r.client.Del(r.ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete cache: %w", err)
	}
	return nil
}

// Exists checks if a key exists in Redis
func (r *RedisClient) Exists(key string) (bool, error) {
	count, err := r.client.Exists(r.ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence: %w", err)
	}
	return count > 0, nil
}

// Increment atomically increments a counter
func (r *RedisClient) Increment(key string, ttl time.Duration) (int64, error) {
	pipe := r.client.TxPipeline()
	
	incr := pipe.Incr(r.ctx, key)
	pipe.Expire(r.ctx, key, ttl)
	
	_, err := pipe.Exec(r.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to increment counter: %w", err)
	}

	return incr.Val(), nil
}

// GetTTL returns the remaining TTL for a key
func (r *RedisClient) GetTTL(key string) (time.Duration, error) {
	ttl, err := r.client.TTL(r.ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get TTL: %w", err)
	}
	return ttl, nil
}

// SetNX sets a key only if it doesn't exist (atomic operation)
func (r *RedisClient) SetNX(key string, value interface{}, ttl time.Duration) (bool, error) {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	result, err := r.client.SetNX(r.ctx, key, jsonData, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("failed to set if not exists: %w", err)
	}

	return result, nil
}

// FlushAll clears all keys (use with caution)
func (r *RedisClient) FlushAll() error {
	err := r.client.FlushAll(r.ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to flush all: %w", err)
	}
	return nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// GetStats returns Redis connection statistics
func (r *RedisClient) GetStats() map[string]interface{} {
	stats := r.client.PoolStats()
	
	return map[string]interface{}{
		"hits":         stats.Hits,
		"misses":       stats.Misses,
		"timeouts":     stats.Timeouts,
		"total_conns":  stats.TotalConns,
		"idle_conns":   stats.IdleConns,
		"stale_conns":  stats.StaleConns,
	}
}

// CacheMiddleware provides HTTP response caching
type CacheMiddleware struct {
	redis *RedisClient
	ttl   time.Duration
}

// NewCacheMiddleware creates a new cache middleware
func NewCacheMiddleware(redis *RedisClient, ttl time.Duration) *CacheMiddleware {
	return &CacheMiddleware{
		redis: redis,
		ttl:   ttl,
	}
}

// CacheResponse represents a cached HTTP response
type CacheResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	Timestamp  time.Time           `json:"timestamp"`
}

// GenerateCacheKey creates a cache key from request details
func (cm *CacheMiddleware) GenerateCacheKey(method, path, query string) string {
	return fmt.Sprintf("cache:%s:%s:%s", method, path, query)
}

// ShouldCache determines if a response should be cached
func (cm *CacheMiddleware) ShouldCache(statusCode int, method string) bool {
	// Only cache successful GET requests
	return method == "GET" && statusCode >= 200 && statusCode < 300
}

// InvalidatePattern removes all cache keys matching a pattern
func (r *RedisClient) InvalidatePattern(pattern string) error {
	keys, err := r.client.Keys(r.ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys for pattern %s: %w", pattern, err)
	}

	if len(keys) > 0 {
		err = r.client.Del(r.ctx, keys...).Err()
		if err != nil {
			return fmt.Errorf("failed to delete keys: %w", err)
		}
	}

	return nil
}

// RateLimitData represents rate limiting information
type RateLimitData struct {
	Count     int64     `json:"count"`
	ResetTime time.Time `json:"reset_time"`
	Limit     int64     `json:"limit"`
}

// CheckRateLimit implements Redis-based rate limiting
func (r *RedisClient) CheckRateLimit(key string, limit int64, window time.Duration) (*RateLimitData, error) {
	now := time.Now()
	windowStart := now.Truncate(window)
	rateLimitKey := fmt.Sprintf("rate_limit:%s:%d", key, windowStart.Unix())

	// Increment counter for this window
	count, err := r.Increment(rateLimitKey, window)
	if err != nil {
		return nil, err
	}

	resetTime := windowStart.Add(window)
	
	return &RateLimitData{
		Count:     count,
		ResetTime: resetTime,
		Limit:     limit,
	}, nil
}

// IsRateLimited checks if the rate limit is exceeded
func (data *RateLimitData) IsRateLimited() bool {
	return data.Count > data.Limit
}

// RemainingRequests returns the number of remaining requests
func (data *RateLimitData) RemainingRequests() int64 {
	remaining := data.Limit - data.Count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// SecondsUntilReset returns seconds until the rate limit resets
func (data *RateLimitData) SecondsUntilReset() int64 {
	return int64(time.Until(data.ResetTime).Seconds())
}
