# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /crypto-server ./services/crypto/cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /crypto-server /crypto-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9092

ENTRYPOINT ["/crypto-server"]
