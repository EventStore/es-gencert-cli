package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateUserCertificate(t *testing.T) {

	t.Run("nominal-case", func(t *testing.T) {

		years := 1
		days := 0
		username := "bob"
		outputDirCA := "./ca"
		outputDirUser := "./user-bob"
		var caCert *x509.Certificate
		var caKey *rsa.PrivateKey
		var userCertFileName = "user-bob"

		// Clean up from previous runs
		os.RemoveAll(outputDirCA)
		os.RemoveAll(outputDirUser)

		certificateError := generateCACertificate(years, days, outputDirCA, caCert, caKey, false)

		certFilePath := path.Join(outputDirCA, "ca.crt")
		keyFilePath := path.Join(outputDirCA, "ca.key")

		_, certPathError := os.Stat(certFilePath)
		_, keyPathError := os.Stat(keyFilePath)

		assert.NoError(t, certificateError)
		assert.False(t, os.IsNotExist(certPathError))
		assert.False(t, os.IsNotExist(keyPathError))

		caCertificate, err := readCertificateFromFile(certFilePath)
		assert.NoError(t, err)
		caPrivateKey, err := readRSAKeyFromFile(keyFilePath)
		assert.NoError(t, err)

		certificateError = generateUserCertificate(username, caCertificate, caPrivateKey, years, days, outputDirUser, userCertFileName)

		userCertPath := path.Join(outputDirUser, "user-bob.crt")
		userKeyPath := path.Join(outputDirUser, "user-bob.key")

		_, userCertPathError := os.Stat(userCertPath)
		_, userKeyPathError := os.Stat(userKeyPath)

		assert.NoError(t, certificateError)
		assert.False(t, os.IsNotExist(userCertPathError))
		assert.False(t, os.IsNotExist(userKeyPathError))

		userCertificate, err := readCertificateFromFile(userCertPath)
		assert.NoError(t, err)

		// verify the subject
		assert.Equal(t, "CN=bob", userCertificate.Subject.String())

		// verify the issuer
		assert.Equal(t, caCertificate.Issuer.String(), userCertificate.Issuer.String())

		// verify the EKUs
		assert.Equal(t, 1, len(userCertificate.ExtKeyUsage))
		assert.Equal(t, x509.ExtKeyUsageClientAuth, userCertificate.ExtKeyUsage[0])
		assert.Equal(t, 0, len(userCertificate.UnknownExtKeyUsage))

		// Clean up
		os.RemoveAll(outputDirCA)
		os.RemoveAll(outputDirUser)
	})
}
