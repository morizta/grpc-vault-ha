package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketSecrets   = []byte("secrets")
	bucketSealState = []byte("seal_state")
	bucketKeyring   = []byte("keyring")

	keySealState = []byte("state")
	keyKeyring   = []byte("data")
)

// BoltStore implements all lock repository interfaces using BoltDB.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore creates a new BoltDB-backed store.
func NewBoltStore(path string) (*BoltStore, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{bucketSecrets, bucketSealState, bucketKeyring} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create buckets: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the BoltDB database.
func (s *BoltStore) Close() error {
	return s.db.Close()
}

// ==================== SecretRepository ====================

func (s *BoltStore) Put(ctx context.Context, path string, secret *Secret) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(secret)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketSecrets).Put([]byte(path), data)
	})
}

func (s *BoltStore) Get(ctx context.Context, path string) (*Secret, error) {
	var secret *Secret
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketSecrets).Get([]byte(path))
		if data == nil {
			return ErrSecretNotFound
		}
		secret = &Secret{}
		return json.Unmarshal(data, secret)
	})
	return secret, err
}

func (s *BoltStore) Delete(ctx context.Context, path string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecrets)
		if b.Get([]byte(path)) == nil {
			return ErrSecretNotFound
		}
		return b.Delete([]byte(path))
	})
}

func (s *BoltStore) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).ForEach(func(k, v []byte) error {
			path := string(k)
			if len(prefix) == 0 || (len(path) >= len(prefix) && path[:len(prefix)] == prefix) {
				keys = append(keys, path)
			}
			return nil
		})
	})
	return keys, err
}

// ==================== SealStateRepository ====================

func (s *BoltStore) Save(ctx context.Context, state *SealState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketSealState).Put(keySealState, data)
	})
}

func (s *BoltStore) Load(ctx context.Context) (*SealState, error) {
	var state *SealState
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketSealState).Get(keySealState)
		if data == nil {
			return ErrSealStateNotFound
		}
		state = &SealState{}
		return json.Unmarshal(data, state)
	})
	return state, err
}

// ==================== KeyringRepository ====================

func (s *BoltStore) SaveKeyring(ctx context.Context, data []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketKeyring).Put(keyKeyring, data)
	})
}

func (s *BoltStore) LoadKeyring(ctx context.Context) ([]byte, error) {
	var result []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketKeyring).Get(keyKeyring)
		if data == nil {
			return ErrKeyringNotFound
		}
		result = make([]byte, len(data))
		copy(result, data)
		return nil
	})
	return result, err
}

// ==================== Interface Adapters ====================

// SecretStore adapts BoltStore to SecretRepository.
type SecretStore struct{ S *BoltStore }

func (a *SecretStore) Put(ctx context.Context, path string, secret *Secret) error { return a.S.Put(ctx, path, secret) }
func (a *SecretStore) Get(ctx context.Context, path string) (*Secret, error)      { return a.S.Get(ctx, path) }
func (a *SecretStore) Delete(ctx context.Context, path string) error              { return a.S.Delete(ctx, path) }
func (a *SecretStore) List(ctx context.Context, prefix string) ([]string, error)  { return a.S.List(ctx, prefix) }

// SealStore adapts BoltStore to SealStateRepository.
type SealStore struct{ S *BoltStore }

func (a *SealStore) Save(ctx context.Context, state *SealState) error { return a.S.Save(ctx, state) }
func (a *SealStore) Load(ctx context.Context) (*SealState, error)     { return a.S.Load(ctx) }

// KeyStore adapts BoltStore to KeyringRepository.
type KeyStore struct{ S *BoltStore }

func (a *KeyStore) Save(ctx context.Context, data []byte) error { return a.S.SaveKeyring(ctx, data) }
func (a *KeyStore) Load(ctx context.Context) ([]byte, error)    { return a.S.LoadKeyring(ctx) }
