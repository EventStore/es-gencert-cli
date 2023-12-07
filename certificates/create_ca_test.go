package certificates

import (
	"bytes"
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateCACertificate(t *testing.T) {
	t.Run("TestCreateCACertificate_NominalCase_ShouldSucceed", TestCreateCACertificate_NominalCase_ShouldSucceed)
	t.Run("TestCreateCACertificate_DifferentOut_ShouldSucceed", TestCreateCACertificate_DifferentOut_ShouldSucceed)
	t.Run("TestCreateCACertificate_WithNameFlag_ShouldCreateNamedCertificates", TestCreateCACertificate_WithNameFlag_ShouldCreateNamedCertificates)
	t.Run("TestCreateCACertificate_WithForceFlag_ShouldRegenerate", TestCreateCACertificate_WithForceFlag_ShouldRegenerate)
	t.Run("TestCreateIntermediateCertificate_WithoutRootCertificate_ShouldFail", TestCreateIntermediateCertificate_WithoutRootCertificate_ShouldFail)
}

func TestCreateCACertificate_NominalCase_ShouldSucceed(t *testing.T) {
	// Create CA certificate and key without any additional parameters.

	t.Parallel()

	cleanup, tempDir, _, _, createCa := setupCreateCaTestEnvironment(t, &TestEnvParams{
		OutputDir: "./ca",
	})
	defer cleanup()

	var args []string

	result := createCa.Run(args)
	assert.Equal(t, 0, result, "creat-ca should pass without any additional parameters")

	assert.FileExists(t, filepath.Join("./ca", "ca.crt"), "CA certificate should exist")
	assert.FileExists(t, filepath.Join("./ca", "ca.key"), "CA key should exist")

	cert, err := readCertificateFromFile(filepath.Join(tempDir, "ca.crt"))
	assert.NoError(t, err, "Failed to read and parse certificate file")

	// The certificate should be valid for 5 year
	expectedNotAfter := time.Now().AddDate(5, 0, 0)
	assert.WithinDuration(t, expectedNotAfter, cert.NotAfter, time.Second, "Certificate validity period does not match expected default")
}

func TestCreateCACertificate_DifferentOut_ShouldSucceed(t *testing.T) {
	// Create certificate with a different output directory.

	t.Parallel()

	cleanup, tempCaDir, _, _, createCa := setupCreateCaTestEnvironment(t, &TestEnvParams{})
	defer cleanup()

	args := []string{"-out", filepath.Join(tempCaDir, "my-custom-dir")}

	result := createCa.Run(args)
	assert.Equal(t, 0, result, "creat-ca should pass with a different output")

	assert.FileExists(t, filepath.Join(tempCaDir, "my-custom-dir", "ca.crt"), "CA certificate should exist")
	assert.FileExists(t, filepath.Join(tempCaDir, "my-custom-dir", "ca.key"), "CA key should exist")
}

func TestCreateCACertificate_WithNameFlag_ShouldCreateNamedCertificates(t *testing.T) {
	// Create CA certificate and key with the name parameter.
	// 1. It creates a certificate with the name parameter
	// 2. The CA certificate and key should be named with the name parameter

	t.Parallel()

	cleanup, tempCaDir, _, _, createCa := setupCreateCaTestEnvironment(t, &TestEnvParams{})
	defer cleanup()

	args := []string{"-out", tempCaDir, "-name", "my-custom-name"}

	result := createCa.Run(args)
	assert.Equal(t, 0, result, "creat-ca should create a certificate with a different name")

	assert.FileExists(t, filepath.Join(tempCaDir, "my-custom-name.crt"), "CA certificate should exist")
	assert.FileExists(t, filepath.Join(tempCaDir, "my-custom-name.key"), "CA certificate should exist")
}

func TestCreateCACertificate_WithForceFlag_ShouldRegenerate(t *testing.T) {
	// Creation of a CA certificate with the force flag.
	// 1. It first creates a certificate
	// 2. Attempt to recreate the certificate with the force flag
	// 3. Check that the content of the files are different

	t.Parallel()

	cleanup, tempCaDir, _, _, createCa := setupCreateCaTestEnvironment(t, &TestEnvParams{})
	defer cleanup()

	// Create a CA certificate
	result := createCa.Run([]string{"-out", tempCaDir})
	assert.Equal(t, 0, result, fmt.Sprintf("creat-ca should pass and create a certificate at %s", tempCaDir))

	// Read the content of the key and crt files
	originalCaCert, originalKeyCert := readAndDecodeCertificateAndKey(t, tempCaDir, "ca")

	// Try to create a CA certificate again with the force flag and override the existing one
	args := []string{"-out", tempCaDir, "-force"}
	result = createCa.Run(args)
	assert.Equal(t, 0, result, fmt.Sprintf("creat-ca should pass and override certificate at %s", tempCaDir))

	// Read the content of the key and crt files generated from the config file
	newCaCert, newKeyCert := readAndDecodeCertificateAndKey(t, tempCaDir, "ca")

	// Check that the content of the files are different
	assert.NotEqual(t, originalCaCert, newCaCert, "The content of the CA certificate should be different")
	assert.NotEqual(t, originalKeyCert, newKeyCert, "The content of the CA key should be different")
}

func TestCreateIntermediateCertificate_WithoutRootCertificate_ShouldFail(t *testing.T) {
	// Create intermediate certificate without root certificate.
	// 1. It creates an intermediate certificate without root certificate
	// 2. It should return an error

	t.Parallel()

	cleanup, tempCaDir, _, errorBuffer, createCa := setupCreateCaTestEnvironment(t, &TestEnvParams{})
	defer cleanup()

	args := []string{
		"-out", tempCaDir,
		"-ca-certificate", "unknown",
		"-ca-key", "unknown",
	}
	result := createCa.Run(args)
	assert.Equal(t, 1, result, "creat-ca should fail without a root certificate")

	errors := extractErrors(errorBuffer.String())
	assert.Equal(t, 1, len(errors), "Expected 1 error")
	assert.Equal(t, "error reading file: open unknown: no such file or directory", errors[0])
}

type TestEnvParams struct {
	OutputDir string
}

func setupCreateCaTestEnvironment(t *testing.T, params *TestEnvParams) (cleanupFunc func(), tempDir string, outputBuffer *bytes.Buffer, errorBuffer *bytes.Buffer, createCa *CreateCA) {
	tempDir = params.OutputDir

	if tempDir == "" {
		var err error
		tempDir, err = os.MkdirTemp(os.TempDir(), "ca-*")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %s", err)
		}
	}

	outputBuffer = new(bytes.Buffer)
	errorBuffer = new(bytes.Buffer)

	createCa = NewCreateCA(&cli.BasicUi{
		Writer:      outputBuffer,
		ErrorWriter: errorBuffer,
	})

	cleanupFunc = func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp directory (%s): %s", tempDir, err)
		}
	}

	return cleanupFunc, tempDir, outputBuffer, errorBuffer, createCa
}
