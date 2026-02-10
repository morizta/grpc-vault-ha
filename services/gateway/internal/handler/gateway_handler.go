package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/pocketsizefund/microservice-vault/gen/go/auth/v1"
	commonv1 "github.com/pocketsizefund/microservice-vault/gen/go/common/v1"
	cryptov1 "github.com/pocketsizefund/microservice-vault/gen/go/crypto/v1"
	lockv1 "github.com/pocketsizefund/microservice-vault/gen/go/lock/v1"
	tokenizev1 "github.com/pocketsizefund/microservice-vault/gen/go/tokenize/v1"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/middleware"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/proxy"
)

// GatewayHandler handles API gateway routing
type GatewayHandler struct {
	logger *zap.Logger
	proxy  *proxy.GRPCProxy
	config *config.Config
}

// NewGatewayHandler creates a new gateway handler
func NewGatewayHandler(logger *zap.Logger, proxy *proxy.GRPCProxy, cfg *config.Config) *GatewayHandler {
	return &GatewayHandler{
		logger: logger,
		proxy:  proxy,
		config: cfg,
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// readJSON reads JSON from request body
func readJSON(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.Unmarshal(body, v)
}

// getIdentityStr returns the authenticated identity string from the request context.
// Returns "anonymous" if no identity is set (unauthenticated paths).
func getIdentityStr(r *http.Request) string {
	if identity, ok := middleware.GetIdentity(r.Context()); ok && identity != nil {
		return identity.Subject
	}
	return "anonymous"
}

// getConnection gets a gRPC connection to a service
func (h *GatewayHandler) getConnection(ctx context.Context, service string) (*grpc.ClientConn, error) {
	var address string
	switch service {
	case "auth":
		address = h.config.Services.AuthAddress
	case "crypto":
		address = h.config.Services.CryptoAddress
	case "tokenize":
		address = h.config.Services.TokenizeAddress
	case "lock":
		address = h.config.Services.LockAddress
	case "audit":
		address = h.config.Services.AuditAddress
	default:
		return nil, nil
	}

	return h.proxy.GetConnection(ctx, service, address)
}

// ========== Crypto Endpoints ==========

// EncryptRequest represents an encrypt request
type EncryptRequest struct {
	KeyName   string `json:"key_name"`
	Plaintext string `json:"plaintext"`
	Context   string `json:"context,omitempty"`
}

// EncryptResponse represents an encrypt response
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
}

// Encrypt handles POST /v1/crypto/encrypt
func (h *GatewayHandler) Encrypt(w http.ResponseWriter, r *http.Request) {
	var req EncryptRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.logger.Debug("Encrypt request",
		zap.String("key_name", req.KeyName),
		zap.String("identity", getIdentityStr(r)))

	// Forward to crypto service via gRPC
	conn, err := h.getConnection(r.Context(), "crypto")
	if err != nil {
		h.logger.Error("Failed to connect to crypto service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "crypto service unavailable")
		return
	}

	client := cryptov1.NewCryptoServiceClient(conn)
	resp, err := client.Encrypt(r.Context(), &cryptov1.EncryptRequest{
		KeyName:   req.KeyName,
		Plaintext: []byte(req.Plaintext),
		Context:   []byte(req.Context),
	})
	if err != nil {
		h.logger.Error("Encrypt failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	writeJSON(w, http.StatusOK, EncryptResponse{
		Ciphertext: resp.Ciphertext,
		KeyVersion: int(resp.KeyVersion),
	})
}

// DecryptRequest represents a decrypt request
type DecryptRequest struct {
	KeyName    string `json:"key_name"`
	Ciphertext string `json:"ciphertext"`
	Context    string `json:"context,omitempty"`
}

// DecryptResponse represents a decrypt response
type DecryptResponse struct {
	Plaintext  string `json:"plaintext"`
	KeyVersion int    `json:"key_version"`
}

// Decrypt handles POST /v1/crypto/decrypt
func (h *GatewayHandler) Decrypt(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.logger.Debug("Decrypt request",
		zap.String("key_name", req.KeyName),
		zap.String("identity", getIdentityStr(r)))

	// Forward to crypto service via gRPC
	conn, err := h.getConnection(r.Context(), "crypto")
	if err != nil {
		h.logger.Error("Failed to connect to crypto service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "crypto service unavailable")
		return
	}

	client := cryptov1.NewCryptoServiceClient(conn)
	resp, err := client.Decrypt(r.Context(), &cryptov1.DecryptRequest{
		KeyName:    req.KeyName,
		Ciphertext: req.Ciphertext,
		Context:    []byte(req.Context),
	})
	if err != nil {
		h.logger.Error("Decrypt failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	writeJSON(w, http.StatusOK, DecryptResponse{
		Plaintext:  string(resp.Plaintext),
		KeyVersion: int(resp.KeyVersion),
	})
}

// ========== Tokenize Endpoints ==========

// TokenizeRequest represents a tokenize request
type TokenizeRequest struct {
	KeyName        string `json:"key_name"`
	Value          string `json:"value"`
	Transformation string `json:"transformation,omitempty"`
}

// TokenizeResponse represents a tokenize response
type TokenizeResponse struct {
	Token      string `json:"token"`
	KeyVersion int    `json:"key_version"`
}

// Tokenize handles POST /v1/tokenize/encode
func (h *GatewayHandler) Tokenize(w http.ResponseWriter, r *http.Request) {
	var req TokenizeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.logger.Debug("Tokenize request",
		zap.String("key_name", req.KeyName),
		zap.String("transformation", req.Transformation),
		zap.String("identity", getIdentityStr(r)))

	// Forward to tokenize service via gRPC
	conn, err := h.getConnection(r.Context(), "tokenize")
	if err != nil {
		h.logger.Error("Failed to connect to tokenize service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "tokenize service unavailable")
		return
	}

	client := tokenizev1.NewTokenizeServiceClient(conn)
	resp, err := client.FPEEncrypt(r.Context(), &tokenizev1.FPEEncryptRequest{
		KeyName:        req.KeyName,
		Plaintext:      req.Value,
		Transformation: req.Transformation,
	})
	if err != nil {
		h.logger.Error("Tokenize failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "tokenization failed")
		return
	}

	writeJSON(w, http.StatusOK, TokenizeResponse{
		Token:      resp.Ciphertext,
		KeyVersion: int(resp.KeyVersion),
	})
}

// DetokenizeRequest represents a detokenize request
type DetokenizeRequest struct {
	KeyName        string `json:"key_name"`
	Token          string `json:"token"`
	Transformation string `json:"transformation,omitempty"`
}

// Detokenize handles POST /v1/tokenize/decode
func (h *GatewayHandler) Detokenize(w http.ResponseWriter, r *http.Request) {
	var req DetokenizeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.logger.Debug("Detokenize request",
		zap.String("key_name", req.KeyName),
		zap.String("transformation", req.Transformation),
		zap.String("identity", getIdentityStr(r)))

	// Forward to tokenize service via gRPC
	conn, err := h.getConnection(r.Context(), "tokenize")
	if err != nil {
		h.logger.Error("Failed to connect to tokenize service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "tokenize service unavailable")
		return
	}

	client := tokenizev1.NewTokenizeServiceClient(conn)
	resp, err := client.FPEDecrypt(r.Context(), &tokenizev1.FPEDecryptRequest{
		KeyName:        req.KeyName,
		Ciphertext:     req.Token,
		Transformation: req.Transformation,
	})
	if err != nil {
		h.logger.Error("Detokenize failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "detokenization failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"value":       resp.Plaintext,
		"key_version": int(resp.KeyVersion),
	})
}

// ========== Lock (Secrets) Endpoints ==========

// SecretRequest represents a secret request
type SecretRequest struct {
	Path string                 `json:"path"`
	Data map[string]interface{} `json:"data,omitempty"`
}

// GetSecret handles GET /v1/secret/data/{path}
func (h *GatewayHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	h.logger.Debug("Get secret request",
		zap.String("path", path),
		zap.String("identity", getIdentityStr(r)))

	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.GetSecret(r.Context(), &lockv1.GetSecretRequest{Path: path})
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.NotFound:
				writeError(w, http.StatusNotFound, "secret not found")
				return
			case codes.FailedPrecondition:
				writeError(w, http.StatusServiceUnavailable, st.Message())
				return
			}
		}
		h.logger.Error("GetSecret failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get secret")
		return
	}

	// Convert []byte values to strings for JSON response
	dataStr := make(map[string]string, len(resp.Data))
	for k, v := range resp.Data {
		dataStr[k] = string(v)
	}

	result := map[string]interface{}{
		"data": dataStr,
		"metadata": map[string]interface{}{
			"path":    resp.Metadata.GetPath(),
			"version": resp.Metadata.GetVersion(),
		},
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": result})
}

// PutSecret handles POST /v1/secret/data/{path}
func (h *GatewayHandler) PutSecret(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")

	var req SecretRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Use path from URL, fallback to body
	if path == "" {
		path = req.Path
	}
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	// Convert data values to bytes for gRPC
	data := make(map[string][]byte)
	for k, v := range req.Data {
		switch val := v.(type) {
		case string:
			data[k] = []byte(val)
		default:
			b, _ := json.Marshal(val)
			data[k] = b
		}
	}

	h.logger.Debug("Put secret request",
		zap.String("path", path),
		zap.String("identity", getIdentityStr(r)))

	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.PutSecret(r.Context(), &lockv1.PutSecretRequest{
		Path: path,
		Data: data,
	})
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.FailedPrecondition {
			writeError(w, http.StatusServiceUnavailable, st.Message())
			return
		}
		h.logger.Error("PutSecret failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to put secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"version": resp.Version,
		},
	})
}

// ========== Auth Endpoints ==========

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
}

// Login handles POST /v1/auth/login
func (h *GatewayHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.logger.Info("Login request",
		zap.String("username", req.Username),
		zap.String("method", req.Method))

	conn, err := h.getConnection(r.Context(), "auth")
	if err != nil {
		h.logger.Error("Failed to connect to auth service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "auth service unavailable")
		return
	}

	client := authv1.NewAuthServiceClient(conn)
	resp, err := client.Authenticate(r.Context(), &authv1.AuthenticateRequest{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unauthenticated {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		h.logger.Error("Authentication failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   resp.ClientToken,
			"accessor":       resp.Accessor,
			"policies":       resp.Policies,
			"token_policies": resp.Policies,
			"lease_duration": resp.LeaseDuration,
			"renewable":      resp.Renewable,
		},
	})
}

// Lookup handles GET /v1/auth/token/lookup-self
func (h *GatewayHandler) Lookup(w http.ResponseWriter, r *http.Request) {
	identity, ok := middleware.GetIdentity(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"id":       identity.Subject,
			"policies": identity.Policies,
			"type":     identity.Type,
		},
	})
}

// ========== Seal Operations ==========

// GetSealStatus handles GET /v1/sys/seal-status
func (h *GatewayHandler) GetSealStatus(w http.ResponseWriter, r *http.Request) {
	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.GetSealStatus(r.Context(), &lockv1.GetSealStatusRequest{})
	if err != nil {
		h.logger.Error("GetSealStatus failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get seal status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sealed":       resp.Sealed,
		"initialized":  resp.Initialized,
		"threshold":    resp.Threshold,
		"shares":       resp.Shares,
		"progress":     resp.Progress,
		"cluster_id":   resp.ClusterId,
		"cluster_name": resp.ClusterName,
		"version":      resp.Version,
	})
}

// InitializeRequest represents an initialize request
type InitializeRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

// Initialize handles POST /v1/sys/init
func (h *GatewayHandler) Initialize(w http.ResponseWriter, r *http.Request) {
	var req InitializeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SecretShares == 0 {
		req.SecretShares = 5
	}
	if req.SecretThreshold == 0 {
		req.SecretThreshold = 3
	}

	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.Initialize(r.Context(), &lockv1.InitializeRequest{
		SecretShares:    int32(req.SecretShares),
		SecretThreshold: int32(req.SecretThreshold),
	})
	if err != nil {
		h.logger.Error("Initialize failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "initialization failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys":        resp.Keys,
		"root_tokens": resp.RootTokens,
	})
}

// UnsealRequest represents an unseal request
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset,omitempty"`
}

// Unseal handles POST /v1/sys/unseal
func (h *GatewayHandler) Unseal(w http.ResponseWriter, r *http.Request) {
	var req UnsealRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.Unseal(r.Context(), &lockv1.UnsealRequest{
		Key:    req.Key,
		Reset_: req.Reset,
	})
	if err != nil {
		h.logger.Error("Unseal failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "unseal failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sealed":      resp.Sealed,
		"initialized": resp.Initialized,
		"threshold":   resp.Threshold,
		"shares":      resp.Shares,
		"progress":    resp.Progress,
	})
}

// Seal handles POST /v1/sys/seal
func (h *GatewayHandler) Seal(w http.ResponseWriter, r *http.Request) {
	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.Seal(r.Context(), &lockv1.SealRequest{})
	if err != nil {
		h.logger.Error("Seal failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "seal failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sealed": resp.Sealed,
	})
}

// ========== Key Management ==========

// CreateKeyRequest represents a create key request
type CreateKeyRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // "aes256-gcm", "chacha20-poly1305", "ed25519", "ecdsa-p256", "rsa-2048", "rsa-4096"
	Exportable bool   `json:"exportable,omitempty"`
}

// CreateKey handles POST /v1/transit/keys
func (h *GatewayHandler) CreateKey(w http.ResponseWriter, r *http.Request) {
	var req CreateKeyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Map type string to proto enum
	keyType := commonv1.KeyType_KEY_TYPE_AES256_GCM // default
	switch req.Type {
	case "aes256-gcm", "aes-256-gcm", "":
		keyType = commonv1.KeyType_KEY_TYPE_AES256_GCM
	case "chacha20-poly1305":
		keyType = commonv1.KeyType_KEY_TYPE_CHACHA20_POLY1305
	case "ed25519":
		keyType = commonv1.KeyType_KEY_TYPE_ED25519
	case "ecdsa-p256":
		keyType = commonv1.KeyType_KEY_TYPE_ECDSA_P256
	case "rsa-2048":
		keyType = commonv1.KeyType_KEY_TYPE_RSA_2048
	case "rsa-4096":
		keyType = commonv1.KeyType_KEY_TYPE_RSA_4096
	}

	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.CreateKey(r.Context(), &lockv1.CreateKeyRequest{
		Name:       req.Name,
		Type:       keyType,
		Exportable: req.Exportable,
	})
	if err != nil {
		h.logger.Error("CreateKey failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "create key failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":           resp.Name,
		"type":           resp.Type.String(),
		"latest_version": resp.LatestVersion,
		"created_at":     resp.CreatedAt,
	})
}

// ListKeys handles GET /v1/transit/keys
func (h *GatewayHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	conn, err := h.getConnection(r.Context(), "lock")
	if err != nil {
		h.logger.Error("Failed to connect to lock service", zap.Error(err))
		writeError(w, http.StatusServiceUnavailable, "lock service unavailable")
		return
	}

	client := lockv1.NewLockServiceClient(conn)
	resp, err := client.ListKeys(r.Context(), &lockv1.ListKeysRequest{})
	if err != nil {
		h.logger.Error("ListKeys failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "list keys failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys": resp.Keys,
	})
}
