package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Oragwel/api-gateway/internal/handlers"
	"github.com/Oragwel/api-gateway/pkg/auth"
	"github.com/Oragwel/api-gateway/pkg/config"
	"github.com/Oragwel/api-gateway/pkg/health"
	"github.com/Oragwel/api-gateway/pkg/metrics"
	"github.com/Oragwel/api-gateway/pkg/middleware"
	"github.com/Oragwel/api-gateway/pkg/proxy"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Gateway represents the main API Gateway application
type Gateway struct {
	config      *config.Config
	router      *gin.Engine
	proxyPool   *proxy.Pool
	authService *auth.Service
	metrics     *metrics.Collector
	health      *health.Checker
}

// NewGateway creates a new API Gateway instance
func NewGateway() (*Gateway, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize components
	authService := auth.NewService(cfg.Auth)
	proxyPool := proxy.NewPool(cfg.Upstream)
	metricsCollector := metrics.NewCollector()
	healthChecker := health.NewChecker(cfg.Health)

	// Setup Gin router
	if cfg.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()

	gateway := &Gateway{
		config:      cfg,
		router:      router,
		proxyPool:   proxyPool,
		authService: authService,
		metrics:     metricsCollector,
		health:      healthChecker,
	}

	gateway.setupMiddleware()
	gateway.setupRoutes()

	return gateway, nil
}

// setupMiddleware configures all middleware for the gateway
func (g *Gateway) setupMiddleware() {
	// Recovery middleware
	g.router.Use(gin.Recovery())

	// CORS middleware
	g.router.Use(middleware.CORS(g.config.CORS))

	// Request logging middleware
	g.router.Use(middleware.Logger())

	// Metrics middleware
	g.router.Use(middleware.Metrics(g.metrics))

	// Rate limiting middleware
	g.router.Use(middleware.RateLimit(g.config.RateLimit))

	// Request ID middleware
	g.router.Use(middleware.RequestID())

	// Security headers middleware
	g.router.Use(middleware.Security())
}

// setupRoutes configures all routes for the gateway
func (g *Gateway) setupRoutes() {
	// Health check endpoints
	g.router.GET("/health", handlers.HealthCheck(g.health))
	g.router.GET("/health/ready", handlers.ReadinessCheck(g.health))
	g.router.GET("/health/live", handlers.LivenessCheck(g.health))

	// Metrics endpoint
	g.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API documentation
	g.router.GET("/docs", handlers.APIDocumentation())
	g.router.Static("/docs/static", "./docs/static")

	// Authentication endpoints
	authGroup := g.router.Group("/auth")
	{
		authGroup.POST("/login", handlers.Login(g.authService))
		authGroup.POST("/refresh", handlers.RefreshToken(g.authService))
		authGroup.POST("/logout", handlers.Logout(g.authService))
		authGroup.GET("/validate", handlers.ValidateToken(g.authService))
	}

	// Protected API routes
	apiGroup := g.router.Group("/api")
	apiGroup.Use(middleware.Authentication(g.authService))
	{
		// Version 1 API
		v1 := apiGroup.Group("/v1")
		{
			v1.Any("/*path", handlers.ProxyRequest(g.proxyPool, "v1"))
		}

		// Version 2 API
		v2 := apiGroup.Group("/v2")
		{
			v2.Any("/*path", handlers.ProxyRequest(g.proxyPool, "v2"))
		}
	}

	// Admin endpoints (with admin authentication)
	adminGroup := g.router.Group("/admin")
	adminGroup.Use(middleware.AdminAuth(g.authService))
	{
		adminGroup.GET("/stats", handlers.GatewayStats(g.metrics))
		adminGroup.GET("/config", handlers.GetConfig(g.config))
		adminGroup.POST("/reload", handlers.ReloadConfig())
		adminGroup.GET("/upstream", handlers.UpstreamStatus(g.proxyPool))
	}

	// WebSocket proxy support
	g.router.GET("/ws/*path", handlers.WebSocketProxy(g.proxyPool))
}

// Start starts the API Gateway server
func (g *Gateway) Start() error {
	// Start health checker
	g.health.Start()

	// Start metrics collection
	g.metrics.Start()

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", g.config.Server.Port),
		Handler:      g.router,
		ReadTimeout:  time.Duration(g.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(g.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(g.config.Server.IdleTimeout) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("🚀 API Gateway starting on port %d", g.config.Server.Port)
		log.Printf("📊 Metrics available at http://localhost:%d/metrics", g.config.Server.Port)
		log.Printf("🏥 Health checks at http://localhost:%d/health", g.config.Server.Port)
		log.Printf("📚 API docs at http://localhost:%d/docs", g.config.Server.Port)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down API Gateway...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown components
	g.health.Stop()
	g.metrics.Stop()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Println("✅ API Gateway stopped gracefully")
	return nil
}

func main() {
	// Create and start the gateway
	gateway, err := NewGateway()
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	if err := gateway.Start(); err != nil {
		log.Fatalf("Gateway startup failed: %v", err)
	}
}
