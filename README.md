# HMAC Validator Package

The `hmacvalidator` package provides a simple yet powerful HMAC validator in Go.
It supports both SHA256 and SHA1 hashing algorithms for HMAC validation.

## Features

- Supports SHA256 and SHA1 HMAC validation.
- Fluent API for HMAC validation.
- Utility methods for both valid and invalid HMAC checks.

## Installation

```bash
go get github.com/xorima/hmacvalidator
```

## Usage

### Initialization

Create a new HMAC validator by specifying the hash type and secret.

```go
import "github.com/xorima/hmacvalidator"

validator := hmacvalidator.NewHMACValidator(hmacvalidator.HashSha256, "your-secret-here")
```

### Validation

Use the IsValid method to validate the HMAC signature of a given body.

```go
body := []byte("your-message-body-here")
signature := "sha256=your-signature-here"

if validator.IsValid(body, signature) {
fmt.Println("Valid signature!")
} else {
fmt.Println("Invalid signature!")
}
```

You can also use the `IsInvalid` method as a convenience for `!IsValid`.

## Versioning

This project adheres to Semantic Versioning (SemVer).
For the versions available, see the tags on this repository.

## Development

### Getting Set Up

Clone the repository:

```bash
git clone https://github.com/xorima/hmacvalidator.git
```

Navigate to the project directory:

```bash
cd hmacvalidator
```

Use the provided Makefile for common development tasks:

- `make lint`: Run golangci-lint on the project.
- `make test`: Run tests for the project.

### Linting

This project uses `golangci-lint` for linting.
Ensure you have it installed or use the provided Makefile to lint the project.

### Testing

Run the tests using the Makefile:

```bash
make test
```

## Contributing
