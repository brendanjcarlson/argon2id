package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

func init() {
	defaultParallelismCost = uint8(runtime.NumCPU())
}

const (
	template        = `$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s`
	versionTemplate = `v=%d`
	paramsTemplate  = `m=%d,t=%d,p=%d`
	splitChar       = "$"

	algorithmIdx = 1
	versionIdx   = 2
	paramsIdx    = 3
	saltIdx      = 4
	keyIdx       = 5

	numParts = 6

	matching = 1
)

const (
	algorithm                = `argon2id`
	defaultTimeCost   uint32 = 2     // 2 iterations
	defaultMemoryCost uint32 = 65536 // 64MB memory cost
	defaultSaltLength uint32 = 16    // bytes
	defaultKeyLength  uint32 = 32    // bytes
)

var defaultParallelismCost uint8

var (
	ErrMalformedHash       = errors.New("malformed hash")
	ErrBytesNotRead        = errors.New("bytes not read")
	ErrPasswordsDoNotMatch = errors.New("passwords do not match")
)

type Argon2Id struct {
	timeCost        uint32
	memoryCost      uint32
	parallelismCost uint8
	saltLength      uint32
	keyLength       uint32
}

// Creates a new Argon2Id instance.
//
// Available options:
//
//	WithTimeCost(uint32) -- 2 or greater is recommended. Default 2.
//	WithMemoryCost(uint32) -- 65536 (64MB) or greater is recommended. Default 65536.
//	WithParallelismCost(uint8) -- 1 or greater is recommended. Default runtime.NumCPU().
//	WithSaltLength(uint32) -- 16 or greater is recommended. Default 16.
//	WithKeyLength(uint32) -- 32 or greater is recommended. Default 32.
func New(options ...Argon2IdOption) *Argon2Id {
	a := &Argon2Id{
		timeCost:        defaultTimeCost,
		memoryCost:      defaultMemoryCost,
		parallelismCost: defaultParallelismCost,
		saltLength:      defaultSaltLength,
		keyLength:       defaultKeyLength,
	}
	if len(options) == 0 {
		return a
	}

	for _, option := range options {
		option(a)
	}
	return a
}

// Generate an argon2id encoded hash from the source bytes.
func (a *Argon2Id) Generate(password []byte) (string, error) {
	salt := make([]byte, a.saltLength, a.saltLength)
	n, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("argon2id: generate salt: %w", err)
	}
	if n != int(a.saltLength) {
		return "", fmt.Errorf("argon2id: generate salt: %w", ErrBytesNotRead)
	}

	key := argon2.IDKey(password, salt, a.timeCost, a.memoryCost, a.parallelismCost, a.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf(template, argon2.Version, a.memoryCost, a.timeCost, a.parallelismCost, b64Salt, b64Key), nil
}

// Compare raw password bytes with an argon2id encoded hash.
func (a *Argon2Id) Compare(password []byte, hash string) error {
	parts := strings.Split(hash, splitChar)
	if len(parts) != numParts {
		return fmt.Errorf("argon2id: parts: %w", ErrMalformedHash)
	}

	if parts[algorithmIdx] != algorithm {
		return fmt.Errorf("argon2id: algorithm: %w", ErrMalformedHash)
	}

	var version int
	if _, err := fmt.Sscanf(parts[versionIdx], versionTemplate, &version); err != nil {
		return fmt.Errorf("argon2id: scan version: %w", err)
	}

	var timeCost, memoryCost uint32
	var parallelismCost uint8
	if _, err := fmt.Sscanf(parts[paramsIdx], paramsTemplate, &memoryCost, &timeCost, &parallelismCost); err != nil {
		return fmt.Errorf("argon2id: scan params: %w", err)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[saltIdx])
	if err != nil {
		return fmt.Errorf("argon2id: decode salt: %w", err)
	}

	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[keyIdx])
	if err != nil {
		return fmt.Errorf("argon2id: decode key: %w", err)
	}

	comparisonKey := argon2.IDKey(password, salt, timeCost, memoryCost, parallelismCost, uint32(len(key)))

	if subtle.ConstantTimeCompare(key, comparisonKey) == matching {
		return nil
	}

	return fmt.Errorf("argon2id: %w", ErrPasswordsDoNotMatch)
}

type Argon2IdOption func(*Argon2Id)

// A value of 2 or greater is recommended.
func WithTimeCost(timeCost uint32) Argon2IdOption {
	return func(a *Argon2Id) { a.timeCost = timeCost }
}

// A value of 64 * 1024 or greater is recommended.
func WithMemoryCost(memoryCost uint32) Argon2IdOption {
	return func(a *Argon2Id) { a.memoryCost = memoryCost }
}

// A value of 1 or greater is recommended.
func WithParallelismCost(parallelismCost uint8) Argon2IdOption {
	return func(a *Argon2Id) { a.parallelismCost = parallelismCost }
}

// A value of 16 or greater is recommended.
func WithSaltLength(saltLength uint32) Argon2IdOption {
	return func(a *Argon2Id) { a.saltLength = saltLength }
}

// A value is 32 or greater is recommended.
func WithKeyLength(keyLength uint32) Argon2IdOption {
	return func(a *Argon2Id) { a.keyLength = keyLength }
}
