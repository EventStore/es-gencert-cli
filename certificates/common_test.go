package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func extractErrors(errorMessage string) []string {
	// Sometimes errors are shown in a multi-line format (multierror.Append), so we need to extract them and return them
	// as a list. However, this method can be used with single line errors as well and will return a list with a single
	// element. Also perform some basic cleanup of the error message (TrimSpace).

	var errors []string

	// Pattern for multi-line errors
	multiLinePattern := regexp.MustCompile(`\* (.+)`)
	multiLineMatches := multiLinePattern.FindAllStringSubmatch(errorMessage, -1)

	if len(multiLineMatches) > 0 {
		for _, match := range multiLineMatches {
			if len(match) > 1 {
				errors = append(errors, strings.TrimSpace(match[1]))
			}
		}
	} else {
		// Single line error
		cleanedError := strings.TrimSpace(errorMessage)
		errors = append(errors, cleanedError)
	}

	return errors
}

func readAndDecodeCertificateAndKey(t *testing.T, dir, name string) (*x509.Certificate, *rsa.PrivateKey) {
	// In the test suite, we often need to verify that a certificate and key pair exist in a given directory.
	// This is usually carried out after a call to the create_ca or create_node commands. This method reads the certificate
	// and key from the given directory and returns them. It will throw an error if the certificate or key cannot be
	// read from the given directory.

	certPath := filepath.Join(dir, fmt.Sprintf("%s.crt", name))
	keyPath := filepath.Join(dir, fmt.Sprintf("%s.key", name))

	ca, caErr := readCertificateFromFile(certPath)
	assert.NoError(t, caErr)

	key, keyErr := readRSAKeyFromFile(keyPath)
	assert.NoError(t, keyErr)

	return ca, key
}
