package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

func assertFilesExist(t *testing.T, files ...string) {
	for _, file := range files {
		_, err := os.Stat(file)
		assert.False(t, os.IsNotExist(err))
	}
}

func generateAndAssertCACert(t *testing.T, years int, days int, outputDirCa string, force bool) (*x509.Certificate, *rsa.PrivateKey) {
	certificateError := generateCACertificate(years, days, outputDirCa, nil, nil, force)
	assert.NoError(t, certificateError)

	certFilePath := path.Join(outputDirCa, "ca.crt")
	keyFilePath := path.Join(outputDirCa, "ca.key")
	assertFilesExist(t, certFilePath, keyFilePath)

	caCertificate, err := readCertificateFromFile(certFilePath)
	assert.NoError(t, err)
	caPrivateKey, err := readRSAKeyFromFile(keyFilePath)
	assert.NoError(t, err)

	return caCertificate, caPrivateKey
}

func cleanupDirsForTest(t *testing.T, dirs ...string) {
	cleanupDirs := func() {
		for _, dir := range dirs {
			os.RemoveAll(dir)
		}
	}

	cleanupDirs()
	t.Cleanup(cleanupDirs)
}
