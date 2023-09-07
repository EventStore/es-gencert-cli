//go:build linux

package certificates

import (
	"crypto/boring"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoringCryptoAvailable(t *testing.T) {
	assert.True(t, boring.Enabled())
}
