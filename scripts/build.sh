#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Services to build
SERVICES=("gateway" "auth" "crypto" "tokenize" "lock" "audit")

# Build output directory
BUILD_DIR="$PROJECT_ROOT/bin"
mkdir -p "$BUILD_DIR"

echo -e "${GREEN}Building microservice-vault services...${NC}"
echo ""

# Parse arguments
BUILD_ALL=true
BUILD_DOCKER=false
TARGET_SERVICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --docker)
            BUILD_DOCKER=true
            shift
            ;;
        --service)
            TARGET_SERVICE="$2"
            BUILD_ALL=false
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Build function
build_service() {
    local service=$1
    echo -e "${YELLOW}Building $service...${NC}"

    # Build binary
    CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
        -o "$BUILD_DIR/${service}-server" \
        "./services/${service}/cmd/server"

    echo -e "${GREEN}✓ $service built successfully${NC}"
}

# Build Docker image
build_docker() {
    local service=$1
    echo -e "${YELLOW}Building Docker image for $service...${NC}"

    docker build \
        -t "microservice-vault/${service}:latest" \
        -f "services/${service}/Dockerfile" \
        .

    echo -e "${GREEN}✓ Docker image for $service built successfully${NC}"
}

# Build services
if [ "$BUILD_ALL" = true ]; then
    for service in "${SERVICES[@]}"; do
        build_service "$service"
        if [ "$BUILD_DOCKER" = true ]; then
            build_docker "$service"
        fi
    done
else
    if [[ " ${SERVICES[@]} " =~ " ${TARGET_SERVICE} " ]]; then
        build_service "$TARGET_SERVICE"
        if [ "$BUILD_DOCKER" = true ]; then
            build_docker "$TARGET_SERVICE"
        fi
    else
        echo -e "${RED}Unknown service: $TARGET_SERVICE${NC}"
        echo "Available services: ${SERVICES[*]}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}Build completed successfully!${NC}"
echo "Binaries are in: $BUILD_DIR"
