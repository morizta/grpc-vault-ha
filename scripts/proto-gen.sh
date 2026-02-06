#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${GREEN}Generating protobuf code...${NC}"

# Check if buf is installed
if ! command -v buf &> /dev/null; then
    echo -e "${YELLOW}buf is not installed. Installing...${NC}"
    go install github.com/bufbuild/buf/cmd/buf@latest
fi

# Check if protoc-gen-go is installed
if ! command -v protoc-gen-go &> /dev/null; then
    echo -e "${YELLOW}protoc-gen-go is not installed. Installing...${NC}"
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

# Check if protoc-gen-go-grpc is installed
if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo -e "${YELLOW}protoc-gen-go-grpc is not installed. Installing...${NC}"
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Generate code using buf
cd "$PROJECT_ROOT/api"

echo -e "${YELLOW}Running buf lint...${NC}"
buf lint || true

echo -e "${YELLOW}Running buf generate...${NC}"
buf generate

echo -e "${GREEN}Protobuf code generation complete!${NC}"
echo "Generated files are in: $PROJECT_ROOT/api/gen"
