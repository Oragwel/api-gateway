# 🚀 Tidings Technologies API Gateway

**Enterprise-grade API Gateway built with Go - High-performance, secure, and scalable**

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue?style=for-the-badge&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://github.com/Oragwel/api-gateway)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)](Dockerfile)

## 📋 Overview

A production-ready API Gateway designed for microservices architecture, featuring advanced routing, authentication, rate limiting, load balancing, and comprehensive monitoring. Built with Go for maximum performance and reliability.

## ✨ Key Features

### 🔐 **Security & Authentication**
- **JWT Authentication** - Secure token-based authentication
- **Role-based Access Control** - Fine-grained permission system
- **API Key Authentication** - Support for API key-based access
- **Rate Limiting** - Configurable rate limiting per IP/user/API key
- **CORS Support** - Cross-origin resource sharing configuration

### 🚀 **Performance & Reliability**
- **Load Balancing** - Round-robin, least connections, weighted algorithms
- **Health Checks** - Automatic upstream service health monitoring
- **Circuit Breaker** - Fault tolerance and resilience patterns
- **Request Timeout** - Configurable timeout handling
- **Graceful Shutdown** - Clean shutdown with connection draining

### 📊 **Monitoring & Observability**
- **Prometheus Metrics** - Comprehensive metrics collection
- **Health Endpoints** - Kubernetes-ready health checks
- **Request Logging** - Structured JSON logging
- **Distributed Tracing** - Request ID tracking
- **Real-time Statistics** - Live gateway performance metrics

### 🔄 **Proxy & Routing**
- **Dynamic Routing** - Path-based and header-based routing
- **WebSocket Support** - WebSocket connection proxying
- **Request/Response Transformation** - Header manipulation
- **Multiple API Versions** - Support for API versioning
- **Upstream Service Discovery** - Dynamic service registration

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client Apps   │───▶│   API Gateway    │───▶│  Microservices  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Monitoring     │
                       │  (Prometheus)    │
                       └──────────────────┘
```

## 🚀 Quick Start

### **Prerequisites**
- Go 1.21 or higher
- Docker (optional)
- Make (optional)

### **Installation**

```bash
# Clone the repository
git clone https://github.com/Oragwel/api-gateway.git
cd api-gateway

# Install dependencies
go mod download

# Build the application
go build -o bin/gateway cmd/gateway/main.go

# Run the gateway
./bin/gateway
```

### **Using Docker**

```bash
# Build Docker image
docker build -t tidings-api-gateway .

# Run with Docker
docker run -p 8080:8080 tidings-api-gateway
```

### **Using Docker Compose**

```bash
# Start the complete stack
docker-compose up -d
```

## ⚙️ Configuration

The gateway is configured via environment variables:

### **Server Configuration**
```bash
SERVER_PORT=8080                    # Server port
SERVER_HOST=0.0.0.0                # Server host
SERVER_MODE=debug                   # debug, release, test
SERVER_READ_TIMEOUT=30              # Read timeout in seconds
SERVER_WRITE_TIMEOUT=30             # Write timeout in seconds
```

### **Authentication Configuration**
```bash
JWT_SECRET=your-secret-key          # JWT signing secret
TOKEN_EXPIRY=15m                    # Access token expiry
REFRESH_EXPIRY=24h                  # Refresh token expiry
ADMIN_USERS=admin@company.com       # Admin user emails
```

### **Rate Limiting Configuration**
```bash
RATE_LIMIT_ENABLED=true             # Enable rate limiting
RATE_LIMIT_RPS=100                  # Requests per second
RATE_LIMIT_BURST=200                # Burst size
RATE_LIMIT_KEY=ip                   # Rate limit key (ip, user, api_key)
```

### **Upstream Services Configuration**
```bash
USER_SERVICE_URL=http://localhost:3001      # User service URL
ORDER_SERVICE_URL=http://localhost:3002     # Order service URL
```

## 📚 API Documentation

### **Health Endpoints**
- `GET /health` - Overall health status
- `GET /health/ready` - Readiness check
- `GET /health/live` - Liveness check

### **Authentication Endpoints**
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - User logout
- `GET /auth/validate` - Validate token

### **API Proxy Endpoints**
- `ANY /api/v1/*` - Proxy to v1 services
- `ANY /api/v2/*` - Proxy to v2 services

### **Admin Endpoints** (Requires admin role)
- `GET /admin/stats` - Gateway statistics
- `GET /admin/config` - Gateway configuration
- `POST /admin/reload` - Reload configuration
- `GET /admin/upstream` - Upstream service status

### **Monitoring Endpoints**
- `GET /metrics` - Prometheus metrics
- `GET /docs` - API documentation

## 🔧 Development

### **Project Structure**
```
api-gateway/
├── cmd/gateway/           # Application entry point
├── pkg/                   # Public packages
│   ├── auth/             # Authentication logic
│   ├── config/           # Configuration management
│   ├── health/           # Health checking
│   ├── metrics/          # Metrics collection
│   ├── middleware/       # HTTP middleware
│   └── proxy/            # Proxy and load balancing
├── internal/             # Private packages
│   ├── handlers/         # HTTP handlers
│   ├── models/           # Data models
│   └── services/         # Business logic
├── deployments/          # Deployment configurations
│   ├── docker/           # Docker files
│   └── k8s/              # Kubernetes manifests
├── docs/                 # Documentation
├── tests/                # Test files
└── examples/             # Usage examples
```

### **Running Tests**
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests
go test -tags=integration ./...
```

### **Building for Production**
```bash
# Build optimized binary
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/gateway cmd/gateway/main.go

# Build Docker image
docker build -t tidings-api-gateway:latest .
```

## 📊 Monitoring

### **Prometheus Metrics**
The gateway exposes comprehensive metrics at `/metrics`:

- **HTTP Metrics**: Request count, duration, response size
- **Upstream Metrics**: Service health, request latency, error rates
- **Authentication Metrics**: Login attempts, token validations
- **Rate Limiting Metrics**: Rate limit hits and blocks
- **System Metrics**: Memory usage, goroutines, uptime

### **Health Checks**
- **Liveness**: `/health/live` - Is the service running?
- **Readiness**: `/health/ready` - Is the service ready to handle requests?
- **Health**: `/health` - Detailed health information

## 🔒 Security

### **Authentication Flow**
1. Client sends credentials to `/auth/login`
2. Gateway validates credentials and returns JWT tokens
3. Client includes JWT in `Authorization: Bearer <token>` header
4. Gateway validates JWT for protected endpoints

### **Default Users**
- **Admin**: `admin@tidingstechnologies.com` / `admin123`
- **User**: `user@tidingstechnologies.com` / `user123`
- **API**: `api@tidingstechnologies.com` / `api123`

## 🚀 Deployment

### **Kubernetes**
```bash
# Apply Kubernetes manifests
kubectl apply -f deployments/k8s/
```

### **Docker Swarm**
```bash
# Deploy to Docker Swarm
docker stack deploy -c docker-compose.yml gateway
```

### **Environment Variables**
See the [Configuration](#configuration) section for all available environment variables.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Otieno Ragwel Rogers**
- GitHub: [@Oragwel](https://github.com/Oragwel)
- Email: tidingstechnologies@gmail.com
- Company: [Tidings Technologies](https://oragwel.github.io/tidings-technologies-website)

## 🙏 Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin) - HTTP web framework
- [Prometheus](https://prometheus.io/) - Monitoring and alerting
- [JWT-Go](https://github.com/golang-jwt/jwt) - JWT implementation
- [Gorilla WebSocket](https://github.com/gorilla/websocket) - WebSocket support

---

<div align="center">

**Built with ❤️ by Tidings Technologies**

[🌐 Website](https://oragwel.github.io/tidings-technologies-website) • [📧 Contact](mailto:tidingstechnologies@gmail.com) • [⭐ Star this repo](https://github.com/Oragwel/api-gateway)

</div>
