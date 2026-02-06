// Package fpe provides Format-Preserving Encryption using FF1 algorithm
package fpe

import (
	"errors"
	"strings"

	"github.com/capitalone/fpe/ff1"
)

// Predefined alphabets
const (
	AlphabetNumeric      = "0123456789"
	AlphabetAlphaLower   = "abcdefghijklmnopqrstuvwxyz"
	AlphabetAlphaUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AlphabetAlphanumeric = AlphabetNumeric + AlphabetAlphaLower + AlphabetAlphaUpper
)

var (
	ErrInvalidAlphabet   = errors.New("invalid alphabet: must have at least 2 characters")
	ErrInvalidPlaintext  = errors.New("plaintext contains characters not in alphabet")
	ErrPlaintextTooShort = errors.New("plaintext too short: minimum 2 characters")
	ErrInvalidKeySize    = errors.New("invalid key size: must be 16, 24, or 32 bytes")
)

// Transformation defines a format-preserving transformation
type Transformation struct {
	Name        string
	Alphabet    string
	Pattern     string // Regex for validation
	Description string
}

// BuiltInTransformations contains predefined transformations
var BuiltInTransformations = map[string]*Transformation{
	"credit-card": {
		Name:        "credit-card",
		Alphabet:    AlphabetNumeric,
		Pattern:     "^[0-9]{13,19}$",
		Description: "Credit card numbers (13-19 digits)",
	},
	"ssn": {
		Name:        "ssn",
		Alphabet:    AlphabetNumeric,
		Pattern:     "^[0-9]{9}$",
		Description: "Social Security Number (9 digits)",
	},
	"phone": {
		Name:        "phone",
		Alphabet:    AlphabetNumeric,
		Pattern:     "^[0-9]{10,15}$",
		Description: "Phone numbers (10-15 digits)",
	},
	"numeric": {
		Name:        "numeric",
		Alphabet:    AlphabetNumeric,
		Pattern:     "^[0-9]+$",
		Description: "Any numeric string",
	},
	"alpha-lower": {
		Name:        "alpha-lower",
		Alphabet:    AlphabetAlphaLower,
		Pattern:     "^[a-z]+$",
		Description: "Lowercase letters only",
	},
	"alpha-upper": {
		Name:        "alpha-upper",
		Alphabet:    AlphabetAlphaUpper,
		Pattern:     "^[A-Z]+$",
		Description: "Uppercase letters only",
	},
	"alphanumeric": {
		Name:        "alphanumeric",
		Alphabet:    AlphabetAlphanumeric,
		Pattern:     "^[a-zA-Z0-9]+$",
		Description: "Letters and numbers",
	},
}

// Cipher provides FF1 FPE operations
type Cipher struct {
	key      []byte
	alphabet string
	radix    int
	cipher   ff1.Cipher
}

// NewCipher creates a new FF1 cipher with the given key and alphabet
func NewCipher(key []byte, alphabet string) (*Cipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	if len(alphabet) < 2 {
		return nil, ErrInvalidAlphabet
	}

	// Create FF1 cipher
	// Parameters: radix, maxTLen (tweak length), key, tweak
	ff1Cipher, err := ff1.NewCipher(len(alphabet), 256, key, nil)
	if err != nil {
		return nil, err
	}

	return &Cipher{
		key:      key,
		alphabet: alphabet,
		radix:    len(alphabet),
		cipher:   ff1Cipher,
	}, nil
}

// NewCipherWithTransformation creates a cipher using a predefined transformation
func NewCipherWithTransformation(key []byte, transformationName string) (*Cipher, error) {
	trans, exists := BuiltInTransformations[transformationName]
	if !exists {
		return nil, errors.New("unknown transformation: " + transformationName)
	}

	return NewCipher(key, trans.Alphabet)
}

// Encrypt encrypts plaintext using FF1, preserving format
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	return c.EncryptWithTweak(plaintext, nil)
}

// EncryptWithTweak encrypts with additional context (tweak)
func (c *Cipher) EncryptWithTweak(plaintext string, tweak []byte) (string, error) {
	if len(plaintext) < 2 {
		return "", ErrPlaintextTooShort
	}

	// Validate plaintext contains only alphabet characters
	if !c.validateString(plaintext) {
		return "", ErrInvalidPlaintext
	}

	// Create cipher with tweak if provided
	var cipher ff1.Cipher
	var err error

	if tweak != nil {
		cipher, err = ff1.NewCipher(c.radix, 256, c.key, tweak)
		if err != nil {
			return "", err
		}
	} else {
		cipher = c.cipher
	}

	// Encrypt - the library uses string representation
	encryptedStr, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	return encryptedStr, nil
}

// Decrypt decrypts ciphertext using FF1
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	return c.DecryptWithTweak(ciphertext, nil)
}

// DecryptWithTweak decrypts with additional context (tweak)
func (c *Cipher) DecryptWithTweak(ciphertext string, tweak []byte) (string, error) {
	if len(ciphertext) < 2 {
		return "", ErrPlaintextTooShort
	}

	// Validate ciphertext contains only alphabet characters
	if !c.validateString(ciphertext) {
		return "", ErrInvalidPlaintext
	}

	// Create cipher with tweak if provided
	var cipher ff1.Cipher
	var err error

	if tweak != nil {
		cipher, err = ff1.NewCipher(c.radix, 256, c.key, tweak)
		if err != nil {
			return "", err
		}
	} else {
		cipher = c.cipher
	}

	// Decrypt - the library uses string representation
	decryptedStr, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}

	return decryptedStr, nil
}

// validateString checks if all characters are in the alphabet
func (c *Cipher) validateString(s string) bool {
	for _, char := range s {
		if !strings.ContainsRune(c.alphabet, char) {
			return false
		}
	}
	return true
}

// stringToNumerals converts a string to numerals based on alphabet position
func (c *Cipher) stringToNumerals(s string) []uint16 {
	numerals := make([]uint16, len(s))
	for i, char := range s {
		numerals[i] = uint16(strings.IndexRune(c.alphabet, char))
	}
	return numerals
}

// numeralsToString converts numerals back to a string
func (c *Cipher) numeralsToString(numerals []uint16) string {
	result := make([]byte, len(numerals))
	for i, n := range numerals {
		result[i] = c.alphabet[n]
	}
	return string(result)
}

// Alphabet returns the alphabet used by this cipher
func (c *Cipher) Alphabet() string {
	return c.alphabet
}

// GetTransformation returns a transformation by name
func GetTransformation(name string) (*Transformation, bool) {
	t, ok := BuiltInTransformations[name]
	return t, ok
}

// ListTransformations returns all built-in transformation names
func ListTransformations() []string {
	names := make([]string, 0, len(BuiltInTransformations))
	for name := range BuiltInTransformations {
		names = append(names, name)
	}
	return names
}
