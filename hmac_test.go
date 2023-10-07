package hmacvalidator

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewHMACValidator_IsValid(t *testing.T) {
	t.Run("should be true for an correct sha256 signature", func(t *testing.T) {
		validator := NewHMACValidator(HashSha256, "foobar")
		got := validator.IsValid([]byte("foo"), "sha256=3d2a9378b1198d88c533bd37abab92c966c59698791bb42661d7c526302ce3e9")
		assert.True(t, got)
	})
	t.Run("should be false for an incorrect sha256 signature", func(t *testing.T) {
		validator := NewHMACValidator(HashSha256, "foobar")
		got := validator.IsValid([]byte("foo"), "bad-signature")
		assert.False(t, got)
	})
	t.Run("should be true for an correct sha1 signature", func(t *testing.T) {
		validator := NewHMACValidator(HashSha1, "foobar")
		got := validator.IsValid([]byte("foo"), "sha1=9160027371254fca708315851425d8888e2f1aa7")
		assert.True(t, got)
	})
	t.Run("should be false for an incorrect sha1 signature", func(t *testing.T) {
		validator := NewHMACValidator(HashSha1, "foobar")
		got := validator.IsValid([]byte("foo"), "bad-signature")
		assert.False(t, got)
	})
	t.Run("returns false if an unknown hash is provided", func(t *testing.T) {
		validator := NewHMACValidator(Hash("foo"), "foobar")
		got := validator.IsValid([]byte("foo"), "bad-signature")
		assert.False(t, got)
	})
}

func TestNewHMACValidator_IsInvalid(t *testing.T) {
	t.Run("should be true for an incorrect sha256 signature", func(t *testing.T) {
		validator := NewHMACValidator(HashSha256, "foobar")
		got := validator.IsInvalid([]byte("foo"), "bad-signature")
		assert.True(t, got)
	})
}
