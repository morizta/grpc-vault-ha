.PHONY: all build test lint proto clean dev dev-infra help

# Variables
GO := go
GOFLAGS := -ldflags="-s -w"
BIN_DIR := bin
SERVICES := gateway auth crypto tokenize lock audit

# Default target
all: lint test build

# Help
help:
	@echo "Microservice Vault Platform"
	@echo ""
	@echo "Usage:"
	@echo "  make proto          Generate protobuf code"
	@echo "  make build          Build all services"
	@echo "  make build-SERVICE  Build specific service (gateway, auth, crypto, tokenize, lock, audit)"
	@echo "  make test           Run all tests"
	@echo "  make lint           Run linter"
	@echo "  make dev-infra      Start development infrastructure (postgres, redis, kafka)"
	@echo "  make dev            Run all services locally"
	@echo "  make clean          Clean build artifacts"
	@echo "  make docker-build   Build Docker images"
	@echo ""

# Generate protobuf
proto:
	@echo "Generating protobuf code..."
	@cd api/proto && buf generate
	@echo "Done!"

# Build all services
build: $(addprefix build-,$(SERVICES))

# Build individual services
build-%:
	@echo "Building $*..."
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/$* ./services/$*/cmd/server

# Test
test:
	@echo "Running tests..."
	$(GO) test -race -coverprofile=coverage.out ./...
	@echo "Done!"

test-coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Development infrastructure
dev-infra:
	@echo "Starting development infrastructure..."
	docker-compose -f deployments/docker-compose.dev.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Infrastructure ready!"

dev-infra-down:
	@echo "Stopping development infrastructure..."
	docker-compose -f deployments/docker-compose.dev.yml down -v

# Run services locally
dev: build
	@echo "Starting services..."
	@./scripts/run-dev.sh

# Docker build
docker-build:
	@echo "Building Docker images..."
	@for service in $(SERVICES); do \
		echo "Building $$service..."; \
		docker build -t vault-$$service:latest -f services/$$service/Dockerfile .; \
	done

docker-push:
	@for service in $(SERVICES); do \
		docker push vault-$$service:latest; \
	done

# Clean
clean:
	@echo "Cleaning..."
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
	rm -rf gen/

# Install tools
tools:
	@echo "Installing tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest

# Tidy dependencies
tidy:
	$(GO) mod tidy

# Vendor dependencies
vendor:
	$(GO) mod vendor

# Security check
security:
	@echo "Running security checks..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi
