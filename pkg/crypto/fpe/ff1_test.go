package fpe

import (
	"testing"
)

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		alphabet  string
		wantErr   bool
		errString string
	}{
		{"valid 16-byte key", 16, AlphabetNumeric, false, ""},
		{"valid 24-byte key", 24, AlphabetNumeric, false, ""},
		{"valid 32-byte key", 32, AlphabetNumeric, false, ""},
		{"invalid 15-byte key", 15, AlphabetNumeric, true, "invalid key size"},
		{"invalid 1-char alphabet", 32, "0", true, "invalid alphabet"},
		{"valid alphanumeric", 32, AlphabetAlphanumeric, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			for i := range key {
				key[i] = byte(i)
			}

			cipher, err := NewCipher(key, tt.alphabet)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cipher == nil {
					t.Errorf("expected cipher but got nil")
				}
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Note: capitalone/fpe library works best with numeric alphabets
	// For non-numeric, results may vary
	tests := []struct {
		name      string
		alphabet  string
		plaintext string
		wantErr   bool
	}{
		{"numeric 10 digits", AlphabetNumeric, "1234567890", false},
		{"numeric 16 digits (credit card)", AlphabetNumeric, "4111111111111111", false},
		{"too short", AlphabetNumeric, "1", true},
		{"invalid chars", AlphabetNumeric, "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCipher(key, tt.alphabet)
			if err != nil {
				t.Fatalf("failed to create cipher: %v", err)
			}

			// Encrypt
			ciphertext, err := cipher.Encrypt(tt.plaintext)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			// Verify format is preserved
			if len(ciphertext) != len(tt.plaintext) {
				t.Errorf("length mismatch: got %d, want %d", len(ciphertext), len(tt.plaintext))
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("decryption mismatch: got %s, want %s", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptDecryptWithTweak(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := NewCipher(key, AlphabetNumeric)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := "1234567890"
	tweak1 := []byte("context1")
	tweak2 := []byte("context2")

	// Encrypt with different tweaks
	ct1, err := cipher.EncryptWithTweak(plaintext, tweak1)
	if err != nil {
		t.Fatalf("encrypt with tweak1 failed: %v", err)
	}

	ct2, err := cipher.EncryptWithTweak(plaintext, tweak2)
	if err != nil {
		t.Fatalf("encrypt with tweak2 failed: %v", err)
	}

	// Different tweaks should produce different ciphertexts
	if ct1 == ct2 {
		t.Errorf("different tweaks produced same ciphertext")
	}

	// Decrypt with correct tweak
	pt1, err := cipher.DecryptWithTweak(ct1, tweak1)
	if err != nil {
		t.Fatalf("decrypt with tweak1 failed: %v", err)
	}

	if pt1 != plaintext {
		t.Errorf("decryption mismatch: got %s, want %s", pt1, plaintext)
	}

	// Decrypt with wrong tweak should produce wrong result
	pt2, err := cipher.DecryptWithTweak(ct1, tweak2)
	if err != nil {
		t.Fatalf("decrypt with wrong tweak failed: %v", err)
	}

	if pt2 == plaintext {
		t.Errorf("wrong tweak should produce different plaintext")
	}
}

func TestTransformations(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name           string
		transformation string
		input          string
	}{
		{"credit-card", "credit-card", "4111111111111111"},
		{"ssn", "ssn", "123456789"},
		{"phone", "phone", "1234567890"},
		{"numeric", "numeric", "9876543210"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCipherWithTransformation(key, tt.transformation)
			if err != nil {
				t.Fatalf("failed to create cipher: %v", err)
			}

			encrypted, err := cipher.Encrypt(tt.input)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			// Verify format preserved
			if len(encrypted) != len(tt.input) {
				t.Errorf("length not preserved: got %d, want %d", len(encrypted), len(tt.input))
			}

			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if decrypted != tt.input {
				t.Errorf("roundtrip failed: got %s, want %s", decrypted, tt.input)
			}
		})
	}
}

func TestGetTransformation(t *testing.T) {
	trans, ok := GetTransformation("credit-card")
	if !ok {
		t.Fatal("credit-card transformation not found")
	}

	if trans.Alphabet != AlphabetNumeric {
		t.Errorf("wrong alphabet: got %s, want %s", trans.Alphabet, AlphabetNumeric)
	}

	_, ok = GetTransformation("unknown")
	if ok {
		t.Error("unknown transformation should not exist")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, _ := NewCipher(key, AlphabetNumeric)
	plaintext := "4111111111111111"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, _ := NewCipher(key, AlphabetNumeric)
	plaintext := "4111111111111111"
	ciphertext, _ := cipher.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Decrypt(ciphertext)
	}
}
