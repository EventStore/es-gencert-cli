package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupTestEnvironment(t *testing.T, override bool) (years int, days int, outputDir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	years = 1
	days = 0
	outputDir = "./ca"
	caCert = nil
	caKey = nil

	t.Cleanup(func() {
		os.RemoveAll(outputDir)
	})

	return
}

func testGenerateCACertificate(t *testing.T, years int, days int, outputDir string, caCert *x509.Certificate, caKey *rsa.PrivateKey, force bool) {
	err := generateCACertificate(years, days, outputDir, caCert, caKey, force)
	assert.NoError(t, err, "Expected no error in nominal case")

	certFilePath := path.Join(outputDir, "ca.crt")
	keyFilePath := path.Join(outputDir, "ca.key")

	certFile, err := readCertificateFromFile(certFilePath)
	assert.NoError(t, err)
	keyFile, err := readRSAKeyFromFile(keyFilePath)
	assert.NoError(t, err)

	err = generateCACertificate(years, days, outputDir, caCert, caKey, force)
	if !force {
		assert.Error(t, err, "Expected an error when directory exists and override is false")
	} else {
		assert.NoError(t, err, "Expected no error when directory exists and override is true")
	}

	certFileAfter, err := readCertificateFromFile(certFilePath)
	assert.NoError(t, err)
	keyFileAfter, err := readRSAKeyFromFile(keyFilePath)
	assert.NoError(t, err)

	if !force {
		assert.Equal(t, certFile, certFileAfter, "Expected CA certificate to be the same")
		assert.Equal(t, keyFile, keyFileAfter, "Expected CA key to be the same")
	} else {
		assert.NotEqual(t, certFile, certFileAfter, "Expected CA certificate to be different")
		assert.NotEqual(t, keyFile, keyFileAfter, "Expected CA key to be different")
	}
}

func TestGenerateCACertificate(t *testing.T) {
	t.Run("nominal-case", func(t *testing.T) {
		years, days, outputDir, caCert, caKey := setupTestEnvironment(t, false)

		err := generateCACertificate(years, days, outputDir, caCert, caKey, false)

		assert.NoError(t, err, "Expected no error in nominal case")

		assert.FileExists(t, path.Join(outputDir, "ca.crt"), "CA certificate should exist")
		assert.FileExists(t, path.Join(outputDir, "ca.key"), "CA key should exist")
	})

	t.Run("directory-exists", func(t *testing.T) {
		years, days, outputDir, caCert, caKey := setupTestEnvironment(t, false)
		testGenerateCACertificate(t, years, days, outputDir, caCert, caKey, false)
	})

	t.Run("directory-exists-force", func(t *testing.T) {
		years, days, outputDir, caCert, caKey := setupTestEnvironment(t, true)
		testGenerateCACertificate(t, years, days, outputDir, caCert, caKey, true)
	})
}
