package hmacvalidator

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

// Hash is a hash type, for example sha256.
type Hash string

const (
	// HashSha256 is the sha256 hash type.
	HashSha256 = Hash("sha256")
	// HashSha1 is the sha1 hash type.
	HashSha1 = Hash("sha1")
)

// Validator is an HMAC validator.
// It can be used to validate HMAC signatures for a given hash and secret.
// The zero value is not valid, use NewHMACValidator instead.
type Validator struct {
	hash   Hash
	secret string
}

// NewHMACValidator returns a new HMAC validator for the given hash and secret.
func NewHMACValidator(hash Hash, secret string) *Validator {
	return &Validator{hash: hash, secret: secret}
}

// IsValid returns true if the signature is valid for the given body
// and secret.
// The signature should be in the format "sha256=xxxxx" or "sha1=xxxxx".
// Inputs
// body []byte - the body to validate
// signature string - the signature to validate the body against
func (v *Validator) IsValid(body []byte, signature string) bool {
	switch v.hash {
	case HashSha256:
		return v.validateSha256(body, signature)
	case HashSha1:
		return v.validateSha1(body, signature)
	}
	return false
}

// Generate will return a signature for the given body
func (v *Validator) Generate(body []byte) string {
	switch v.hash {
	case HashSha256:
		return v.generateSha256(body)
	case HashSha1:
		return v.generateSha1(body)
	}
	return ""
}

// IsInvalid returns true if the signature is invalid for the given body
// and secret.
// This is a convenience method for !IsValid(body, signature)
// Inputs
// body []byte - the body to validate
// signature string - the signature to validate the body against
func (v *Validator) IsInvalid(body []byte, signature string) bool {
	return !v.IsValid(body, signature)
}

func (v *Validator) validateSha256(body []byte, signature string) bool {
	return hmac.Equal([]byte(signature), []byte(v.generateSha256(body)))
}

func (v *Validator) generateSha256(body []byte) string {
	mac := hmac.New(sha256.New, []byte(v.secret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	return "sha256=" + hex.EncodeToString(expectedMAC)
}

func (v *Validator) validateSha1(body []byte, signature string) bool {
	return hmac.Equal([]byte(signature), []byte(v.generateSha1(body)))
}

func (v *Validator) generateSha1(body []byte) string {
	mac := hmac.New(sha1.New, []byte(v.secret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	return "sha1=" + hex.EncodeToString(expectedMAC)

}
