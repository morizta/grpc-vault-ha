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

	// Convert from custom alphabet to base-N numeral string that big.Int can parse.
	// The capitalone/fpe library uses big.Int.SetString(X, radix) internally, so
	// each character must represent its index in the alphabet using standard base-N digits.
	numeralStr := c.alphabetToNumeralStr(plaintext)
	encryptedNumeral, err := cipher.Encrypt(numeralStr)
	if err != nil {
		return "", err
	}

	// Convert result back from base-N numeral string to custom alphabet characters
	return c.numeralStrToAlphabet(encryptedNumeral), nil
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

	// Convert from custom alphabet to base-N numeral string
	numeralStr := c.alphabetToNumeralStr(ciphertext)
	decryptedNumeral, err := cipher.Decrypt(numeralStr)
	if err != nil {
		return "", err
	}

	// Convert result back to custom alphabet characters
	return c.numeralStrToAlphabet(decryptedNumeral), nil
}

// alphabetToNumeralStr converts custom alphabet string to base-N digit string
// that big.Int.SetString(X, radix) can parse correctly.
// Mapping: alphabet index i → digit char using Go's base-62 encoding
//
//	0-9   → '0'-'9'
//	10-35 → 'a'-'z'
//	36-61 → 'A'-'Z'
//
// This is identical to identity for AlphabetNumeric (radix=10), so no behavior change
// for existing numeric use cases.
func (c *Cipher) alphabetToNumeralStr(s string) string {
	result := make([]byte, len(s))
	for i, char := range s {
		idx := strings.IndexRune(c.alphabet, char)
		result[i] = indexToDigitChar(idx)
	}
	return string(result)
}

// numeralStrToAlphabet converts a base-N digit string back to custom alphabet characters
func (c *Cipher) numeralStrToAlphabet(s string) string {
	result := make([]byte, len(s))
	for i, char := range s {
		idx := digitCharToIndex(char)
		if idx >= 0 && idx < len(c.alphabet) {
			result[i] = c.alphabet[idx]
		}
	}
	return string(result)
}

// indexToDigitChar converts an alphabet index (0-61) to the digit character
// used by Go's big.Int for that value in any base up to 62.
func indexToDigitChar(idx int) byte {
	switch {
	case idx < 10:
		return byte('0' + idx)
	case idx < 36:
		return byte('a' + (idx - 10))
	default:
		return byte('A' + (idx - 36))
	}
}

// digitCharToIndex converts a big.Int digit character back to an alphabet index.
func digitCharToIndex(ch rune) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'a' && ch <= 'z':
		return int(ch-'a') + 10
	case ch >= 'A' && ch <= 'Z':
		return int(ch-'A') + 36
	default:
		return 0
	}
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
