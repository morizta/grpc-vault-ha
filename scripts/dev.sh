#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Default action
ACTION="${1:-start}"

case $ACTION in
    start)
        echo -e "${GREEN}Starting development environment...${NC}"

        # Start infrastructure
        docker-compose -f deployments/docker-compose.dev.yml up -d

        echo -e "${YELLOW}Waiting for services to be ready...${NC}"
        sleep 5

        echo -e "${GREEN}Development environment started!${NC}"
        echo ""
        echo "Services:"
        echo "  - PostgreSQL: localhost:5432"
        echo "  - Redis: localhost:6379"
        echo "  - Jaeger UI: http://localhost:16686"
        echo "  - Prometheus: http://localhost:9000"
        echo "  - Grafana: http://localhost:3000"
        echo ""
        echo "To run services locally:"
        echo "  go run ./services/gateway/cmd/server"
        echo "  go run ./services/auth/cmd/server"
        echo "  go run ./services/crypto/cmd/server"
        echo "  go run ./services/tokenize/cmd/server"
        echo "  go run ./services/lock/cmd/server"
        echo "  go run ./services/audit/cmd/server"
        ;;

    stop)
        echo -e "${YELLOW}Stopping development environment...${NC}"
        docker-compose -f deployments/docker-compose.dev.yml down
        echo -e "${GREEN}Development environment stopped!${NC}"
        ;;

    restart)
        $0 stop
        $0 start
        ;;

    logs)
        SERVICE="${2:-}"
        if [ -n "$SERVICE" ]; then
            docker-compose -f deployments/docker-compose.dev.yml logs -f "$SERVICE"
        else
            docker-compose -f deployments/docker-compose.dev.yml logs -f
        fi
        ;;

    status)
        docker-compose -f deployments/docker-compose.dev.yml ps
        ;;

    clean)
        echo -e "${YELLOW}Cleaning up development environment...${NC}"
        docker-compose -f deployments/docker-compose.dev.yml down -v --remove-orphans
        echo -e "${GREEN}Cleanup complete!${NC}"
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|logs|status|clean}"
        echo ""
        echo "Commands:"
        echo "  start   - Start development infrastructure"
        echo "  stop    - Stop development infrastructure"
        echo "  restart - Restart development infrastructure"
        echo "  logs    - View logs (optional: service name)"
        echo "  status  - Show container status"
        echo "  clean   - Remove all containers and volumes"
        exit 1
        ;;
esac
