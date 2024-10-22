# argon2id

## Robust, secure password hashing

<code>argon2id</code> is a Go package for generating and comparing password hashes using the argon2id algorithm.

## Installation

```bash
go get -u github.com/brendanjcarlson/argon2id
```

## Usage

### With default configuration

```go
package main

import "github.com/brendanjcarlson/argon2id"

func main() {
    // Create a new *argon2id.Argon2Id instance with default configuration.
    arg2 := argon2id.New()

    password := "super-secret"

    passwordHash, err := arg2.Generate([]byte(hash))
    if err != nil {
        log.Fatalln(err);
    }
    // passwordHash is now securely hashed and is safe to store in a database.

    err := arg2.Compare([]byte("super-secret"), passwordHash)
    if errors.Is(err, argon2id.ErrPasswordsDoNotMatch) {
        panic("YOU SHALL NOT PASS!")
    } else if err != nil {
        log.Fatalln(err)
    }
}
```

### With custom configuration

```go
package main

import "github.com/brendanjcarlson/argon2id"

func main() {
    arg2 := argon2id.New(
        argon2id.WithTimeCost(4), // default 2
        argon2id.WithMemoryCost(32 * 1024), // default 64 * 1024 (64MB)
        argon2id.WithParallelismCost(2), // default runtime.NumCPU()
        argon2id.WithSaltLength(48), // default 16
        argon2id.WithKeyLength(64), // default 32
    )

    // ...
}
```

## Documentation

See user documentation at <https://pkg.go.dev/github.com/brendanjcarlson/argon2id>

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request on GitHub.
