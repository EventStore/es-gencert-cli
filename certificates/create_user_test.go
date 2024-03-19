package certificates

import (
	"bytes"
	"crypto/x509"
	"github.com/mitchellh/cli"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateUserCertificate(t *testing.T) {
	t.Run("TestCreateUserCertificate_WithoutParams_ShouldFail", TestCreateUserCertificate_WithoutParams_ShouldFail)
	t.Run("TestCreateUserCertificate_WithAllRequiredParams_ShouldSucceed", TestCreateUserCertificate_WithAllRequiredParams_ShouldSucceed)
	t.Run("TestCreateUserCertificate_WithNegativeDays_ShouldFail", TestCreateUserCertificate_WithNegativeDays_ShouldFail)
	t.Run("TestCreateUserCertificate_WithForceFlag_ShouldRegenerate", TestCreateUserCertificate_WithForceFlag_ShouldRegenerate)
}

func TestCreateUserCertificate_WithoutParams_ShouldFail(t *testing.T) {
	t.Parallel()

	cleanup, _, _, _, errorBuffer, createUser := setupCreateUserTestEnvironment(t)
	defer cleanup()

	var args []string
	result := createUser.Run(args)

	assert.Equal(t, 1, result, "The 'create-user' operation should fail due to the absence of required parameters.")

	errors := extractErrors(errorBuffer.String())
	assert.Equal(t, 1, len(errors))
	assert.Equal(t, "username is a required field", errors[0])
}

func TestCreateUserCertificate_WithAllRequiredParams_ShouldSucceed(t *testing.T) {
	t.Parallel()

	cleanup, tempUserDir, tempCaDir, _, _, createUser := setupCreateUserTestEnvironment(t)
	defer cleanup()

	username := "ouro"
	args := []string{
		"-username", username,
		"-ca-certificate", filepath.Join(tempCaDir, "ca.crt"),
		"-ca-key", filepath.Join(tempCaDir, "ca.key"),
		"-out", tempUserDir,
	}

	if result := createUser.Run(args); result != 0 {
		t.Fatalf("Expected 0, got %d", result)
	}

	userFmt := "user-" + username
	userCertPath := filepath.Join(tempUserDir, userFmt+".crt")
	userKeyPath := filepath.Join(tempUserDir, userFmt+".key")

	assert.FileExists(t, userCertPath, "User certificate should exist")
	assert.FileExists(t, userKeyPath, "User key should exist")

	cert, err := readCertificateFromFile(userCertPath)
	assert.NoError(t, err, "Failed to read and parse certificate file")

	expectedNotAfter := time.Now().AddDate(1, 0, 0)
	assert.WithinDuration(t, expectedNotAfter, cert.NotAfter, time.Second, "Certificate validity period does not match expected default")

	caCert, err := readCertificateFromFile(filepath.Join(tempCaDir, "ca.crt"))
	assert.NoError(t, err, "Failed to read and parse CA certificate file")

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	assert.NoError(t, err, "User certificate should be signed by the provided root CA")
}

func TestCreateUserCertificate_WithNegativeDays_ShouldFail(t *testing.T) {
	t.Parallel()

	cleanup, _, tempCaDir, _, errorBuffer, createUser := setupCreateUserTestEnvironment(t)
	defer cleanup()

	args := []string{
		"-username", "ouro",
		"-ca-certificate", filepath.Join(tempCaDir, "ca.crt"),
		"-ca-key", filepath.Join(tempCaDir, "ca.key"),
		"-days", "-1",
	}
	result := createUser.Run(args)

	assert.Equal(t, 1, result, "The 'create-user' operation should fail when days is negative.")

	errors := extractErrors(errorBuffer.String())
	assert.Equal(t, 1, len(errors))
	assert.Equal(t, "days must be positive", errors[0])
}

func TestCreateUserCertificate_WithForceFlag_ShouldRegenerate(t *testing.T) {
	t.Parallel()

	cleanup, tempUserDir, tempCaDir, _, _, createUser := setupCreateUserTestEnvironment(t)
	defer cleanup()

	username := "ouro"
	args := []string{
		"-username", username,
		"-ca-certificate", filepath.Join(tempCaDir, "ca.crt"),
		"-ca-key", filepath.Join(tempCaDir, "ca.key"),
		"-out", tempUserDir,
	}

	result := createUser.Run(args)

	userFmt := "user-" + username
	originalUserCert, originalUserKey := readAndDecodeCertificateAndKey(t, tempUserDir, userFmt)

	updatedArgs := append(args, "-force")
	result = createUser.Run(updatedArgs)
	assert.Equal(t, 0, result, "The 'create-user' should override the existing certificate with the --force flag")

	newUserCert, newUserKey := readAndDecodeCertificateAndKey(t, tempUserDir, userFmt)

	assert.NotEqual(t, originalUserCert, newUserCert, "The User certificate should be different")
	assert.NotEqual(t, originalUserKey, newUserKey, "The User key should be different")
}

func setupCreateUserTestEnvironment(t *testing.T) (cleanupFunc func(), tempUserDir string, tempCaDir string, outputBuffer *bytes.Buffer, errorBuffer *bytes.Buffer, createUser *CreateUser) {
	var err error

	tempUserDir, err = os.MkdirTemp(os.TempDir(), "user-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err)
	}

	tempCaDir, err = os.MkdirTemp(os.TempDir(), "ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err)
	}

	outputBuffer = new(bytes.Buffer)
	errorBuffer = new(bytes.Buffer)

	createUser = NewCreateUser(&cli.BasicUi{
		Writer:      outputBuffer,
		ErrorWriter: errorBuffer,
	})

	// We need to create a root CA file to be able to create a user certificate
	createCa := NewCreateCA(&cli.BasicUi{
		Writer:      new(bytes.Buffer),
		ErrorWriter: new(bytes.Buffer),
	})

	args := []string{"-out", tempCaDir}
	if result := createCa.Run(args); result != 0 {
		t.Fatalf("Expected 0, got %d", result)
	}

	cleanupFunc = func() {
		if err := os.RemoveAll(tempUserDir); err != nil {
			t.Logf("Failed to remove temp user directory (%s): %s", tempUserDir, err)
		}
		if err := os.RemoveAll(tempCaDir); err != nil {
			t.Logf("Failed to remove temp ca directory (%s): %s", tempCaDir, err)
		}
	}

	return cleanupFunc, tempUserDir, tempCaDir, outputBuffer, errorBuffer, createUser
}
