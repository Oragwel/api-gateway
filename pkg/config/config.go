package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the complete configuration for the API Gateway
type Config struct {
	Server    ServerConfig    `json:"server" yaml:"server"`
	Auth      AuthConfig      `json:"auth" yaml:"auth"`
	Upstream  UpstreamConfig  `json:"upstream" yaml:"upstream"`
	RateLimit RateLimitConfig `json:"rate_limit" yaml:"rate_limit"`
	CORS      CORSConfig      `json:"cors" yaml:"cors"`
	Health    HealthConfig    `json:"health" yaml:"health"`
	Logging   LoggingConfig   `json:"logging" yaml:"logging"`
	Metrics   MetricsConfig   `json:"metrics" yaml:"metrics"`
	Redis     RedisConfig     `json:"redis" yaml:"redis"`
	Cache     CacheConfig     `json:"cache" yaml:"cache"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Port         int    `json:"port" yaml:"port"`
	Host         string `json:"host" yaml:"host"`
	Mode         string `json:"mode" yaml:"mode"` // debug, release, test
	ReadTimeout  int    `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout int    `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout  int    `json:"idle_timeout" yaml:"idle_timeout"`
	TLS          struct {
		Enabled  bool   `json:"enabled" yaml:"enabled"`
		CertFile string `json:"cert_file" yaml:"cert_file"`
		KeyFile  string `json:"key_file" yaml:"key_file"`
	} `json:"tls" yaml:"tls"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	JWTSecret     string        `json:"jwt_secret" yaml:"jwt_secret"`
	TokenExpiry   time.Duration `json:"token_expiry" yaml:"token_expiry"`
	RefreshExpiry time.Duration `json:"refresh_expiry" yaml:"refresh_expiry"`
	Issuer        string        `json:"issuer" yaml:"issuer"`
	Audience      string        `json:"audience" yaml:"audience"`
	AdminUsers    []string      `json:"admin_users" yaml:"admin_users"`
}

// UpstreamConfig contains upstream service configuration
type UpstreamConfig struct {
	Services map[string]ServiceConfig `json:"services" yaml:"services"`
}

// ServiceConfig represents configuration for an upstream service
type ServiceConfig struct {
	Name            string            `json:"name" yaml:"name"`
	URL             string            `json:"url" yaml:"url"`
	HealthCheckPath string            `json:"health_check_path" yaml:"health_check_path"`
	Timeout         time.Duration     `json:"timeout" yaml:"timeout"`
	Retries         int               `json:"retries" yaml:"retries"`
	LoadBalancer    string            `json:"load_balancer" yaml:"load_balancer"` // round_robin, least_conn, ip_hash
	Headers         map[string]string `json:"headers" yaml:"headers"`
	Instances       []InstanceConfig  `json:"instances" yaml:"instances"`
}

// InstanceConfig represents a service instance
type InstanceConfig struct {
	URL    string `json:"url" yaml:"url"`
	Weight int    `json:"weight" yaml:"weight"`
	Health string `json:"health" yaml:"health"` // healthy, unhealthy, unknown
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	RequestsPerSecond int           `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size"`
	KeyFunc           string        `json:"key_func" yaml:"key_func"` // ip, user, api_key
}

// CORSConfig contains CORS configuration
type CORSConfig struct {
	Enabled          bool     `json:"enabled" yaml:"enabled"`
	AllowedOrigins   []string `json:"allowed_origins" yaml:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods" yaml:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers" yaml:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers" yaml:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials" yaml:"allow_credentials"`
	MaxAge           int      `json:"max_age" yaml:"max_age"`
}

// HealthConfig contains health check configuration
type HealthConfig struct {
	Enabled          bool          `json:"enabled" yaml:"enabled"`
	CheckInterval    time.Duration `json:"check_interval" yaml:"check_interval"`
	Timeout          time.Duration `json:"timeout" yaml:"timeout"`
	FailureThreshold int           `json:"failure_threshold" yaml:"failure_threshold"`
	SuccessThreshold int           `json:"success_threshold" yaml:"success_threshold"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `json:"level" yaml:"level"`   // debug, info, warn, error
	Format     string `json:"format" yaml:"format"` // json, text
	Output     string `json:"output" yaml:"output"` // stdout, file
	FilePath   string `json:"file_path" yaml:"file_path"`
	MaxSize    int    `json:"max_size" yaml:"max_size"`
	MaxBackups int    `json:"max_backups" yaml:"max_backups"`
	MaxAge     int    `json:"max_age" yaml:"max_age"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Path      string `json:"path" yaml:"path"`
	Namespace string `json:"namespace" yaml:"namespace"`
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
	PoolSize int    `json:"pool_size" yaml:"pool_size"`
}

// CacheConfig contains caching configuration
type CacheConfig struct {
	Enabled    bool          `json:"enabled" yaml:"enabled"`
	DefaultTTL time.Duration `json:"default_ttl" yaml:"default_ttl"`
	MaxSize    int           `json:"max_size" yaml:"max_size"`
	Strategy   string        `json:"strategy" yaml:"strategy"` // redis, memory, hybrid
}

// Load loads configuration from environment variables with sensible defaults
func Load() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Port:         getEnvAsInt("SERVER_PORT", 8080),
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Mode:         getEnv("SERVER_MODE", "debug"),
			ReadTimeout:  getEnvAsInt("SERVER_READ_TIMEOUT", 30),
			WriteTimeout: getEnvAsInt("SERVER_WRITE_TIMEOUT", 30),
			IdleTimeout:  getEnvAsInt("SERVER_IDLE_TIMEOUT", 120),
		},
		Auth: AuthConfig{
			JWTSecret:     getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
			TokenExpiry:   getEnvAsDuration("TOKEN_EXPIRY", "15m"),
			RefreshExpiry: getEnvAsDuration("REFRESH_EXPIRY", "24h"),
			Issuer:        getEnv("JWT_ISSUER", "tidings-api-gateway"),
			Audience:      getEnv("JWT_AUDIENCE", "tidings-services"),
			AdminUsers:    getEnvAsSlice("ADMIN_USERS", []string{"admin@tidingstechnologies.com"}),
		},
		RateLimit: RateLimitConfig{
			Enabled:           getEnvAsBool("RATE_LIMIT_ENABLED", true),
			RequestsPerSecond: getEnvAsInt("RATE_LIMIT_RPS", 100),
			BurstSize:         getEnvAsInt("RATE_LIMIT_BURST", 200),
			WindowSize:        getEnvAsDuration("RATE_LIMIT_WINDOW", "1m"),
			KeyFunc:           getEnv("RATE_LIMIT_KEY", "ip"),
		},
		CORS: CORSConfig{
			Enabled:          getEnvAsBool("CORS_ENABLED", true),
			AllowedOrigins:   getEnvAsSlice("CORS_ORIGINS", []string{"*"}),
			AllowedMethods:   getEnvAsSlice("CORS_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			AllowedHeaders:   getEnvAsSlice("CORS_HEADERS", []string{"*"}),
			ExposedHeaders:   getEnvAsSlice("CORS_EXPOSED", []string{"X-Request-ID"}),
			AllowCredentials: getEnvAsBool("CORS_CREDENTIALS", true),
			MaxAge:           getEnvAsInt("CORS_MAX_AGE", 86400),
		},
		Health: HealthConfig{
			Enabled:          getEnvAsBool("HEALTH_ENABLED", true),
			CheckInterval:    getEnvAsDuration("HEALTH_INTERVAL", "30s"),
			Timeout:          getEnvAsDuration("HEALTH_TIMEOUT", "5s"),
			FailureThreshold: getEnvAsInt("HEALTH_FAILURE_THRESHOLD", 3),
			SuccessThreshold: getEnvAsInt("HEALTH_SUCCESS_THRESHOLD", 2),
		},
		Logging: LoggingConfig{
			Level:      getEnv("LOG_LEVEL", "info"),
			Format:     getEnv("LOG_FORMAT", "json"),
			Output:     getEnv("LOG_OUTPUT", "stdout"),
			FilePath:   getEnv("LOG_FILE_PATH", "/var/log/gateway.log"),
			MaxSize:    getEnvAsInt("LOG_MAX_SIZE", 100),
			MaxBackups: getEnvAsInt("LOG_MAX_BACKUPS", 3),
			MaxAge:     getEnvAsInt("LOG_MAX_AGE", 28),
		},
		Metrics: MetricsConfig{
			Enabled:   getEnvAsBool("METRICS_ENABLED", true),
			Path:      getEnv("METRICS_PATH", "/metrics"),
			Namespace: getEnv("METRICS_NAMESPACE", "gateway"),
		},
		Redis: RedisConfig{
			Enabled:  getEnvAsBool("REDIS_ENABLED", true),
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnvAsInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
			PoolSize: getEnvAsInt("REDIS_POOL_SIZE", 10),
		},
		Cache: CacheConfig{
			Enabled:    getEnvAsBool("CACHE_ENABLED", true),
			DefaultTTL: getEnvAsDuration("CACHE_DEFAULT_TTL", "5m"),
			MaxSize:    getEnvAsInt("CACHE_MAX_SIZE", 1000),
			Strategy:   getEnv("CACHE_STRATEGY", "redis"),
		},
	}

	// Load upstream services configuration
	config.Upstream = loadUpstreamConfig()

	return config, nil
}

// loadUpstreamConfig loads upstream service configuration
func loadUpstreamConfig() UpstreamConfig {
	services := make(map[string]ServiceConfig)

	// Example service configurations (can be loaded from file or env)
	services["user-service"] = ServiceConfig{
		Name:            "user-service",
		URL:             getEnv("USER_SERVICE_URL", "http://localhost:3001"),
		HealthCheckPath: "/health",
		Timeout:         getEnvAsDuration("USER_SERVICE_TIMEOUT", "30s"),
		Retries:         getEnvAsInt("USER_SERVICE_RETRIES", 3),
		LoadBalancer:    "round_robin",
		Headers: map[string]string{
			"X-Service": "user-service",
		},
		Instances: []InstanceConfig{
			{URL: getEnv("USER_SERVICE_URL", "http://localhost:3001"), Weight: 1, Health: "unknown"},
		},
	}

	services["order-service"] = ServiceConfig{
		Name:            "order-service",
		URL:             getEnv("ORDER_SERVICE_URL", "http://localhost:3002"),
		HealthCheckPath: "/health",
		Timeout:         getEnvAsDuration("ORDER_SERVICE_TIMEOUT", "30s"),
		Retries:         getEnvAsInt("ORDER_SERVICE_RETRIES", 3),
		LoadBalancer:    "round_robin",
		Headers: map[string]string{
			"X-Service": "order-service",
		},
		Instances: []InstanceConfig{
			{URL: getEnv("ORDER_SERVICE_URL", "http://localhost:3002"), Weight: 1, Health: "unknown"},
		},
	}

	return UpstreamConfig{Services: services}
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue string) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	duration, _ := time.ParseDuration(defaultValue)
	return duration
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret cannot be empty")
	}

	if len(c.Upstream.Services) == 0 {
		return fmt.Errorf("at least one upstream service must be configured")
	}

	return nil
}
