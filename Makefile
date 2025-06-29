# Tidings Technologies API Gateway Makefile
# Author: Otieno Ragwel Rogers

# Variables
BINARY_NAME=gateway
BINARY_PATH=bin/$(BINARY_NAME)
DOCKER_IMAGE=tidings-api-gateway
DOCKER_TAG=latest
GO_VERSION=1.21

# Build information
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(BUILD_DATE)"

.PHONY: help build run test clean docker docker-run docker-compose deps lint fmt vet security

# Default target
all: clean deps test build

# Help target
help: ## Show this help message
	@echo "Tidings Technologies API Gateway"
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
deps: ## Download dependencies
	@echo "📦 Downloading dependencies..."
	go mod download
	go mod tidy

build: ## Build the application
	@echo "🔨 Building $(BINARY_NAME)..."
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build $(LDFLAGS) -a -installsuffix cgo -o $(BINARY_PATH) cmd/gateway/main.go
	@echo "✅ Build complete: $(BINARY_PATH)"

build-local: ## Build for local development
	@echo "🔨 Building $(BINARY_NAME) for local development..."
	mkdir -p bin
	go build $(LDFLAGS) -o $(BINARY_PATH) cmd/gateway/main.go
	@echo "✅ Local build complete: $(BINARY_PATH)"

run: build-local ## Build and run the application
	@echo "🚀 Starting $(BINARY_NAME)..."
	./$(BINARY_PATH)

run-dev: ## Run with live reload (requires air)
	@echo "🔄 Starting development server with live reload..."
	air

# Testing targets
test: ## Run tests
	@echo "🧪 Running tests..."
	go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "📊 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report generated: coverage.html"

test-integration: ## Run integration tests
	@echo "🔗 Running integration tests..."
	go test -v -tags=integration ./...

benchmark: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	go test -bench=. -benchmem ./...

# Code quality targets
fmt: ## Format code
	@echo "🎨 Formatting code..."
	go fmt ./...

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	go vet ./...

lint: ## Run golangci-lint
	@echo "🔍 Running linter..."
	golangci-lint run

security: ## Run security checks
	@echo "🔒 Running security checks..."
	gosec ./...

# Docker targets
docker: ## Build Docker image
	@echo "🐳 Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

docker-run: docker ## Build and run Docker container
	@echo "🐳 Running Docker container..."
	docker run -p 8080:8080 --name $(BINARY_NAME) $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-stop: ## Stop Docker container
	@echo "🛑 Stopping Docker container..."
	docker stop $(BINARY_NAME) || true
	docker rm $(BINARY_NAME) || true

docker-compose: ## Start with Docker Compose
	@echo "🐳 Starting with Docker Compose..."
	docker-compose up -d

docker-compose-logs: ## View Docker Compose logs
	@echo "📋 Viewing Docker Compose logs..."
	docker-compose logs -f

docker-compose-down: ## Stop Docker Compose
	@echo "🛑 Stopping Docker Compose..."
	docker-compose down

# Deployment targets
deploy-k8s: ## Deploy to Kubernetes
	@echo "☸️ Deploying to Kubernetes..."
	kubectl apply -f deployments/k8s/

undeploy-k8s: ## Remove from Kubernetes
	@echo "🗑️ Removing from Kubernetes..."
	kubectl delete -f deployments/k8s/

# Utility targets
clean: ## Clean build artifacts
	@echo "🧹 Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean

install-tools: ## Install development tools
	@echo "🛠️ Installing development tools..."
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

generate: ## Generate code (mocks, etc.)
	@echo "⚙️ Generating code..."
	go generate ./...

mod-update: ## Update dependencies
	@echo "📦 Updating dependencies..."
	go get -u ./...
	go mod tidy

# Database targets (if needed)
migrate-up: ## Run database migrations up
	@echo "⬆️ Running migrations up..."
	# Add migration command here

migrate-down: ## Run database migrations down
	@echo "⬇️ Running migrations down..."
	# Add migration command here

# Documentation targets
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	godoc -http=:6060
	@echo "📚 Documentation available at http://localhost:6060"

# Release targets
release: clean test build docker ## Build release version
	@echo "🎉 Release build complete!"

# Development workflow
dev-setup: deps install-tools ## Setup development environment
	@echo "🛠️ Development environment setup complete!"

dev-check: fmt vet lint test ## Run all checks
	@echo "✅ All checks passed!"

# Show build info
info: ## Show build information
	@echo "Build Information:"
	@echo "  Version: $(VERSION)"
	@echo "  Commit: $(COMMIT)"
	@echo "  Build Date: $(BUILD_DATE)"
	@echo "  Go Version: $(GO_VERSION)"

# Quick development cycle
quick: fmt vet build ## Quick build cycle (format, vet, build)
	@echo "⚡ Quick build complete!"
