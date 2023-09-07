//go:build windows

package certificates

// Currently boringcryptography is only supported on Linux
func isBoringEnabled() bool {
	return false
}
