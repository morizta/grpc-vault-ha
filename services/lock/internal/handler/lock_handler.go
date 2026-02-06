package handler

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/pocketsizefund/microservice-vault/gen/go/common/v1"
	lockv1 "github.com/pocketsizefund/microservice-vault/gen/go/lock/v1"
	"github.com/pocketsizefund/microservice-vault/pkg/crypto/keyring"
	"github.com/pocketsizefund/microservice-vault/services/lock/internal/service"
)

// LockHandler implements the gRPC LockService
type LockHandler struct {
	lockv1.UnimplementedLockServiceServer
	service *service.LockService
	logger  *zap.Logger
}

// NewLockHandler creates a new lock handler
func NewLockHandler(svc *service.LockService, logger *zap.Logger) *LockHandler {
	return &LockHandler{
		service: svc,
		logger:  logger,
	}
}

// Register registers the handler with a gRPC server
func (h *LockHandler) Register(server *grpc.Server) {
	lockv1.RegisterLockServiceServer(server, h)
}

// GetSealStatus returns the current seal status
func (h *LockHandler) GetSealStatus(ctx context.Context, req *lockv1.GetSealStatusRequest) (*lockv1.SealStatus, error) {
	sealed, initialized, threshold, progress := h.service.GetSealStatus()

	return &lockv1.SealStatus{
		Sealed:      sealed,
		Initialized: initialized,
		Threshold:   int32(threshold),
		Progress:    int32(progress),
	}, nil
}

// Initialize initializes the vault
func (h *LockHandler) Initialize(ctx context.Context, req *lockv1.InitializeRequest) (*lockv1.InitializeResponse, error) {
	keys, rootToken, err := h.service.Initialize(ctx, int(req.SecretShares), int(req.SecretThreshold))
	if err != nil {
		if err == service.ErrAlreadyInitialized {
			return nil, status.Error(codes.AlreadyExists, "vault already initialized")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.InitializeResponse{
		Keys:       keys,
		RootTokens: []string{rootToken},
	}, nil
}

// Unseal attempts to unseal the vault
func (h *LockHandler) Unseal(ctx context.Context, req *lockv1.UnsealRequest) (*lockv1.SealStatus, error) {
	unsealed, progress, err := h.service.Unseal(ctx, req.Key)
	if err != nil {
		if err == service.ErrNotInitialized {
			return nil, status.Error(codes.FailedPrecondition, "vault not initialized")
		}
		if err == service.ErrInvalidKey {
			return nil, status.Error(codes.InvalidArgument, "invalid unseal key")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	_, initialized, threshold, _ := h.service.GetSealStatus()

	return &lockv1.SealStatus{
		Sealed:      !unsealed,
		Initialized: initialized,
		Threshold:   int32(threshold),
		Progress:    int32(progress),
	}, nil
}

// Seal seals the vault
func (h *LockHandler) Seal(ctx context.Context, req *lockv1.SealRequest) (*lockv1.SealStatus, error) {
	if err := h.service.Seal(ctx); err != nil {
		if err == service.ErrNotInitialized {
			return nil, status.Error(codes.FailedPrecondition, "vault not initialized")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	sealed, initialized, threshold, progress := h.service.GetSealStatus()
	return &lockv1.SealStatus{
		Sealed:      sealed,
		Initialized: initialized,
		Threshold:   int32(threshold),
		Progress:    int32(progress),
	}, nil
}

// GetSecret retrieves a secret
func (h *LockHandler) GetSecret(ctx context.Context, req *lockv1.GetSecretRequest) (*lockv1.GetSecretResponse, error) {
	secret, err := h.service.GetSecret(ctx, req.Path)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == service.ErrSecretNotFound {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.GetSecretResponse{
		Data: secret.Data,
		Metadata: &lockv1.SecretMetadata{
			Path:           req.Path,
			Version:        int32(secret.Version),
			CurrentVersion: int32(secret.Version),
			CreatedAt:      secret.CreatedAt.Unix(),
			UpdatedAt:      secret.UpdatedAt.Unix(),
		},
	}, nil
}

// PutSecret stores a secret
func (h *LockHandler) PutSecret(ctx context.Context, req *lockv1.PutSecretRequest) (*lockv1.PutSecretResponse, error) {
	version, err := h.service.PutSecret(ctx, req.Path, req.Data)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.PutSecretResponse{
		Version: int32(version),
	}, nil
}

// DeleteSecret deletes a secret
func (h *LockHandler) DeleteSecret(ctx context.Context, req *lockv1.DeleteSecretRequest) (*lockv1.DeleteSecretResponse, error) {
	if err := h.service.DeleteSecret(ctx, req.Path); err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == service.ErrSecretNotFound {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &lockv1.DeleteSecretResponse{}, nil
}

// ListSecrets lists secrets under a path
func (h *LockHandler) ListSecrets(ctx context.Context, req *lockv1.ListSecretsRequest) (*lockv1.ListSecretsResponse, error) {
	keys, err := h.service.ListSecrets(ctx, req.PathPrefix)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &lockv1.ListSecretsResponse{Keys: keys}, nil
}

// GetSecretMetadata gets secret metadata
func (h *LockHandler) GetSecretMetadata(ctx context.Context, req *lockv1.GetSecretMetadataRequest) (*lockv1.GetSecretMetadataResponse, error) {
	secret, err := h.service.GetSecret(ctx, req.Path)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == service.ErrSecretNotFound {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.GetSecretMetadataResponse{
		Metadata: &lockv1.SecretMetadata{
			Path:           req.Path,
			Version:        int32(secret.Version),
			CurrentVersion: int32(secret.Version),
			CreatedAt:      secret.CreatedAt.Unix(),
			UpdatedAt:      secret.UpdatedAt.Unix(),
		},
	}, nil
}

// protoKeyTypeToKeyring converts proto KeyType to keyring.KeyType
func protoKeyTypeToKeyring(kt commonv1.KeyType) keyring.KeyType {
	switch kt {
	case commonv1.KeyType_KEY_TYPE_AES256_GCM:
		return keyring.KeyTypeAES256GCM
	case commonv1.KeyType_KEY_TYPE_CHACHA20_POLY1305:
		return keyring.KeyTypeChacha20Poly1305
	case commonv1.KeyType_KEY_TYPE_RSA_2048:
		return keyring.KeyTypeRSA2048
	case commonv1.KeyType_KEY_TYPE_RSA_4096:
		return keyring.KeyTypeRSA4096
	case commonv1.KeyType_KEY_TYPE_ECDSA_P256:
		return keyring.KeyTypeECDSAP256
	case commonv1.KeyType_KEY_TYPE_ED25519:
		return keyring.KeyTypeEd25519
	default:
		return keyring.KeyTypeAES256GCM
	}
}

// keyringKeyTypeToProto converts keyring.KeyType to proto KeyType
func keyringKeyTypeToProto(kt keyring.KeyType) commonv1.KeyType {
	switch kt {
	case keyring.KeyTypeAES256GCM:
		return commonv1.KeyType_KEY_TYPE_AES256_GCM
	case keyring.KeyTypeChacha20Poly1305:
		return commonv1.KeyType_KEY_TYPE_CHACHA20_POLY1305
	case keyring.KeyTypeRSA2048:
		return commonv1.KeyType_KEY_TYPE_RSA_2048
	case keyring.KeyTypeRSA4096:
		return commonv1.KeyType_KEY_TYPE_RSA_4096
	case keyring.KeyTypeECDSAP256:
		return commonv1.KeyType_KEY_TYPE_ECDSA_P256
	case keyring.KeyTypeEd25519:
		return commonv1.KeyType_KEY_TYPE_ED25519
	default:
		return commonv1.KeyType_KEY_TYPE_AES256_GCM
	}
}

// CreateKey creates a new encryption key
func (h *LockHandler) CreateKey(ctx context.Context, req *lockv1.CreateKeyRequest) (*lockv1.CreateKeyResponse, error) {
	keyType := protoKeyTypeToKeyring(req.Type)

	if err := h.service.CreateKey(ctx, req.Name, keyType); err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.CreateKeyResponse{
		Name:          req.Name,
		Type:          req.Type,
		LatestVersion: 1,
		CreatedAt:     time.Now().Unix(),
	}, nil
}

// GetKey returns key information
func (h *LockHandler) GetKey(ctx context.Context, req *lockv1.GetKeyRequest) (*lockv1.GetKeyResponse, error) {
	policy, err := h.service.GetKey(ctx, req.Name)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == keyring.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.GetKeyResponse{
		Name:                 policy.Name,
		Type:                 keyringKeyTypeToProto(policy.Type),
		LatestVersion:        int32(policy.LatestVersion),
		MinDecryptionVersion: int32(policy.MinDecryptionVersion),
		MinEncryptionVersion: int32(policy.MinEncryptionVersion),
		Exportable:           policy.Exportable,
	}, nil
}

// DeleteKey deletes a key
func (h *LockHandler) DeleteKey(ctx context.Context, req *lockv1.DeleteKeyRequest) (*lockv1.DeleteKeyResponse, error) {
	// For now, deletion is not supported
	return nil, status.Error(codes.Unimplemented, "key deletion not supported")
}

// GetEncryptionKey returns the raw key material (internal use only)
func (h *LockHandler) GetEncryptionKey(ctx context.Context, req *lockv1.GetEncryptionKeyRequest) (*lockv1.GetEncryptionKeyResponse, error) {
	key, err := h.service.GetEncryptionKey(ctx, req.Name, int(req.Version))
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == keyring.ErrKeyNotFound || err == keyring.ErrVersionNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &lockv1.GetEncryptionKeyResponse{
		Key:     key.Key,
		Version: int32(key.Version),
		Type:    keyringKeyTypeToProto(key.Type),
	}, nil
}

// RotateKey creates a new version of the key
func (h *LockHandler) RotateKey(ctx context.Context, req *lockv1.RotateKeyRequest) (*lockv1.RotateKeyResponse, error) {
	version, err := h.service.RotateKey(ctx, req.Name)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == keyring.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &lockv1.RotateKeyResponse{NewVersion: int32(version)}, nil
}

// ListKeys returns all key names
func (h *LockHandler) ListKeys(ctx context.Context, req *lockv1.ListKeysRequest) (*lockv1.ListKeysResponse, error) {
	keys, err := h.service.ListKeys(ctx)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &lockv1.ListKeysResponse{Keys: keys}, nil
}

// UpdateKeyConfig updates key configuration
func (h *LockHandler) UpdateKeyConfig(ctx context.Context, req *lockv1.UpdateKeyConfigRequest) (*lockv1.UpdateKeyConfigResponse, error) {
	// Not fully implemented yet
	return &lockv1.UpdateKeyConfigResponse{}, nil
}

// GetKeyVersions returns all versions of a key
func (h *LockHandler) GetKeyVersions(ctx context.Context, req *lockv1.GetKeyVersionsRequest) (*lockv1.GetKeyVersionsResponse, error) {
	// Simplified implementation - return just the latest version
	policy, err := h.service.GetKey(ctx, req.Name)
	if err != nil {
		if err == service.ErrSealed {
			return nil, status.Error(codes.FailedPrecondition, "vault is sealed")
		}
		if err == keyring.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	versions := make([]*lockv1.KeyVersion, policy.LatestVersion)
	for i := 1; i <= policy.LatestVersion; i++ {
		versions[i-1] = &lockv1.KeyVersion{
			Version:   int32(i),
			CreatedAt: time.Now().Unix(), // Simplified
		}
	}

	return &lockv1.GetKeyVersionsResponse{Versions: versions}, nil
}

// GetLeader returns cluster leader info
func (h *LockHandler) GetLeader(ctx context.Context, req *lockv1.GetLeaderRequest) (*lockv1.GetLeaderResponse, error) {
	return &lockv1.GetLeaderResponse{
		LeaderAddress: "localhost:8082",
		IsSelf:        true,
	}, nil
}

// JoinCluster joins a cluster
func (h *LockHandler) JoinCluster(ctx context.Context, req *lockv1.JoinClusterRequest) (*lockv1.JoinClusterResponse, error) {
	return &lockv1.JoinClusterResponse{}, nil
}

// LeaveCluster leaves a cluster
func (h *LockHandler) LeaveCluster(ctx context.Context, req *lockv1.LeaveClusterRequest) (*lockv1.LeaveClusterResponse, error) {
	return &lockv1.LeaveClusterResponse{}, nil
}

// GetClusterStatus returns cluster status
func (h *LockHandler) GetClusterStatus(ctx context.Context, req *lockv1.GetClusterStatusRequest) (*lockv1.ClusterStatus, error) {
	return &lockv1.ClusterStatus{
		ClusterId:     "standalone",
		ClusterName:   "default",
		LeaderAddress: "localhost:8082",
	}, nil
}
