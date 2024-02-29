package certificates

import (
	"crypto/x509"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupTestEnvironmentForUserTests(t *testing.T) (years int, days int, username string, userCertFileName string, outputDirCa string, outputDirUser string) {
	years = 1
	days = 0
	username = "bob"
	userCertFileName = "user-" + username
	outputDirCa = "./ca"
	outputDirUser = "./" + userCertFileName

	cleanupDirsForTest(t, outputDirCa, outputDirUser)
	return
}

func TestGenerateUserCertificate(t *testing.T) {

	t.Run("nominal-case", func(t *testing.T) {
		years, days, username, userCertFileName, outputDirCa, outputDirUser := setupTestEnvironmentForUserTests(t)

		caCertificate, caPrivateKey := generateAndAssertCACert(t, years, days, outputDirCa, false)

		err := generateUserCertificate(username, userCertFileName, caCertificate, caPrivateKey, years, days, outputDirUser, false)
		assert.NoError(t, err)

		userCertPath := path.Join(outputDirUser, userCertFileName+".crt")
		userKeyPath := path.Join(outputDirUser, userCertFileName+".key")
		assertFilesExist(t, userCertPath, userKeyPath)

		userCertificate, _ := readCertificateFromFile(userCertPath)

		// verify the subject
		assert.Equal(t, "CN="+username, userCertificate.Subject.String())

		// verify the issuer
		assert.Equal(t, caCertificate.Issuer.String(), userCertificate.Issuer.String())

		// verify the EKUs
		assert.Equal(t, 1, len(userCertificate.ExtKeyUsage))
		assert.Equal(t, x509.ExtKeyUsageClientAuth, userCertificate.ExtKeyUsage[0])
		assert.Equal(t, 0, len(userCertificate.UnknownExtKeyUsage))
	})

	t.Run("force-flag", func(t *testing.T) {
		years, days, username, userCertFileName, outputDirCa, outputDirUser := setupTestEnvironmentForUserTests(t)

		caCertificate, caPrivateKey := generateAndAssertCACert(t, years, days, outputDirCa, false)

		err := generateUserCertificate(username, userCertFileName, caCertificate, caPrivateKey, years, days, outputDirUser, false)
		assert.NoError(t, err)

		userCertPath := path.Join(outputDirUser, userCertFileName+".crt")
		userKeyPath := path.Join(outputDirUser, userCertFileName+".key")
		assertFilesExist(t, userCertPath, userKeyPath)

		userCertificate, _ := readCertificateFromFile(userCertPath)
		userCertificateKey, _ := readRSAKeyFromFile(userKeyPath)

		// try to generate again without force
		err = generateUserCertificate(username, userCertFileName, caCertificate, caPrivateKey, years, days, outputDirUser, false)
		assert.Error(t, err)
		userCertificateAfter, err := readCertificateFromFile(userCertPath)
		assert.NoError(t, err)
		userCertificateKeyAfter, err := readRSAKeyFromFile(userKeyPath)
		assert.NoError(t, err)
		assert.Equal(t, userCertificate, userCertificateAfter, "Expected user certificate to be the same")
		assert.Equal(t, userCertificateKey, userCertificateKeyAfter, "Expected user key to be the same")

		// try to generate again with force
		err = generateUserCertificate(username, userCertFileName, caCertificate, caPrivateKey, years, days, outputDirUser, true)
		assert.NoError(t, err)
		userCertificateAfterWithForce, err := readCertificateFromFile(userCertPath)
		assert.NoError(t, err)
		userCertificateKeyAfterWithForce, err := readRSAKeyFromFile(userKeyPath)
		assert.NoError(t, err)
		assert.NotEqual(t, userCertificate, userCertificateAfterWithForce, "Expected user certificate to be different")
		assert.NotEqual(t, userCertificateKey, userCertificateKeyAfterWithForce, "Expected user key to be different")
	})
}
