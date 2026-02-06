# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /auth-server ./services/auth/cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /auth-server /auth-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9091

ENTRYPOINT ["/auth-server"]
