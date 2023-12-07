//go:build linux

package certificates

import (
	"crypto/boring"
)

func isBoringEnabled() bool {
	return boring.Enabled()
}
