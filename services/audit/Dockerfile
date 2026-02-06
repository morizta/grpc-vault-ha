# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /audit-server ./services/audit/cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /audit-server /audit-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9095

ENTRYPOINT ["/audit-server"]
