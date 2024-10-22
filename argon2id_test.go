package argon2id

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func newArgon2IdWithRandomConfig() *Argon2Id {
	return New(
		WithTimeCost(uint32(max(1, rand.Int31n(8)))),
		WithMemoryCost(uint32(max(1024, rand.Int31n(128*1024)))),
		WithParallelismCost(uint8(max(1, rand.Int31n(int32(runtime.NumCPU()))))),
		WithSaltLength(uint32(max(1, rand.Int31n(128)))),
		WithKeyLength(uint32(max(1, rand.Int31n(128)))),
	)
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345689!@#$%^&*()_-=+,.;<>[]{}`'\"\\/|?~"

func generateRandomString(n int) string {
	var out strings.Builder
	for range n {
		out.WriteByte(charset[rand.Intn(len(charset))])
	}
	return out.String()
}

func assert(t *testing.T, truthy bool, msg string, args ...any) {
	if !truthy {
		t.Fatalf(msg, args...)
	}
}

func assertGenerate(t *testing.T, gotHash string, wantErr error, gotErr error) {
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("generate err: want %v, got %v", wantErr, gotErr)
	}
	if len(gotHash) == 0 {
		t.Fatalf("generate hash: value is empty")
	}
}

func assertCompare(t *testing.T, wantErr error, gotErr error) {
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("compare err: want %v, got %v", wantErr, gotErr)
	}
}

func TestArgon2Id(t *testing.T) {
	iters := 25
	if count := os.Getenv("TEST_ITERS"); count != "" {
		iters, _ = strconv.Atoi(count)
	}

	for range iters {
		a := newArgon2IdWithRandomConfig()
		testname := fmt.Sprintf("timeCost:%d memoryCost:%d parallelismCost:%d saltLength:%d keyLength:%d",
			a.timeCost, a.memoryCost, a.parallelismCost, a.saltLength, a.keyLength,
		)
		t.Run(testname, func(t *testing.T) {
			for range iters {
				source := generateRandomString(max(1, rand.Intn(32)))
				comparison := generateRandomString(max(1, rand.Intn(32))) + "_wrong" // ensure we don't have a 1 in a bazillion chance of generating the same random string
				sourceBytes := []byte(source)
				comparisonBytes := []byte(comparison)
				t.Run(source, func(t *testing.T) {
					hash, err := a.Generate(sourceBytes)
					assertGenerate(t, hash, nil, err)

					rehash, err := a.Generate(sourceBytes)
					assertGenerate(t, rehash, nil, err)

					assert(t, hash != rehash, "generate: hash and rehash should be unique: \nhash %s\n, rehash %s\n", hash, rehash)

					err = a.Compare(sourceBytes, hash)
					assertCompare(t, nil, err)

					err = a.Compare(sourceBytes, rehash)
					assertCompare(t, nil, err)

					err = a.Compare(comparisonBytes, hash)
					assertCompare(t, ErrPasswordsDoNotMatch, err)

					err = a.Compare(comparisonBytes, rehash)
					assertCompare(t, ErrPasswordsDoNotMatch, err)
				})
			}
		})
	}
}
