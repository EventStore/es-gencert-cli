package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCACertificate(t *testing.T) {

	t.Run("nominal-case", func(t *testing.T) {
		years := 1
		days := 0
		outputDir := "./ca"
		var caCert *x509.Certificate
		var caKey *rsa.PrivateKey

		// Clean up from previous runs
		os.RemoveAll(outputDir)

		certificateError := generateCACertificate(years, days, outputDir, caCert, caKey)

		certFilePath := path.Join(outputDir, "ca.crt")
		keyFilePath := path.Join(outputDir, "ca.key")

		_, certPathError := os.Stat(certFilePath)
		_, keyPathError := os.Stat(keyFilePath)

		assert.NoError(t, certificateError)
		assert.False(t, os.IsNotExist(certPathError))
		assert.False(t, os.IsNotExist(keyPathError))

		// Clean up
		os.RemoveAll(outputDir)

	})

}
