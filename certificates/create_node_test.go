package certificates

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateNodeCertificate(t *testing.T) {
	t.Run("TestCreateNodeCertificate_WithoutParams_ShouldFail", TestCreateNodeCertificate_WithoutParams_ShouldFail)
	t.Run("TestCreateNodeCertificate_WithAllRequiredParams_ShouldSucceed", TestCreateNodeCertificate_WithAllRequiredParams_ShouldSucceed)
	t.Run("TestCreateNodeCertificate_WithNameFlagAndOutput_ShouldCreateNamedCertificate", TestCreateNodeCertificate_WithNameFlagAndOutput_ShouldCreateNamedCertificate)
	t.Run("TestCreateNodeCertificate_WithNameFlagWithoutOutput_ShouldCreateNamedCertificate", TestCreateNodeCertificate_WithNameFlagWithoutOutput_ShouldCreateNamedCertificate)
	t.Run("TestCreateNodeCertificate_WithForceFlag_ShouldRegenerate", TestCreateNodeCertificate_WithForceFlag_ShouldRegenerate)
}

func TestCreateNodeCertificate_WithoutParams_ShouldFail(t *testing.T) {
	t.Parallel()

	cleanup, _, _, _, errorBuffer, createNode := setupCreateNodeTestEnvironment(t)
	defer cleanup()

	var args []string
	result := createNode.Run(args)
	assert.Equal(t, 1, result, "The 'create-node' operation should fail due to the absence of required parameters.")

	errors := extractErrors(errorBuffer.String())
	assert.Equal(t, 1, len(errors))
	assert.Equal(t, "at least one IP address or DNS name needs to be specified with --ip-addresses or --dns-names", errors[0])
}

func TestCreateNodeCertificate_WithAllRequiredParams_ShouldSucceed(t *testing.T) {
	t.Parallel()

	cleanup, tempNodeDir, tempCaDir, _, _, createNode := setupCreateNodeTestEnvironment(t)
	defer cleanup()

	args := []string{
		"-ca-certificate", filepath.Join(tempCaDir, "ca.crt"),
		"-ca-key", filepath.Join(tempCaDir, "ca.key"),
		"-out", tempNodeDir,
		"-ip-addresses", "127.0.0.1",
		"-dns-names", "localhost",
	}
	if result := createNode.Run(args); result != 0 {
		t.Fatalf("Expected 0, got %d", result)
	}

	assert.FileExists(t, filepath.Join(tempNodeDir, "node.crt"), "Node certificate should exist")
	assert.FileExists(t, filepath.Join(tempNodeDir, "node.key"), "Node key should exist")

	cert, err := readCertificateFromFile(filepath.Join(tempNodeDir, "node.crt"))
	assert.NoError(t, err, "Failed to read and parse certificate file")

	expectedNotAfter := time.Now().AddDate(1, 0, 0)
	assert.WithinDuration(t, expectedNotAfter, cert.NotAfter, time.Second, "Certificate validity period does not match expected default")

	caCert, err := readCertificateFromFile(filepath.Join(tempCaDir, "ca.crt"))
	assert.NoError(t, err, "Failed to read and parse CA certificate file")

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	assert.NoError(t, err, "Node certificate should be signed by the provided root CA")
}

func TestCreateNodeCertificate_WithNameFlagAndOutput_ShouldCreateNamedCertificate(t *testing.T) {
	t.Parallel()

	cleanup, tempNodeDir, tempCaDir, _, _, createNode := setupCreateNodeTestEnvironment(t)
	defer cleanup()

	args := []string{
		"-ca-certificate", fmt.Sprintf("%s/ca.crt", tempCaDir),
		"-ca-key", fmt.Sprintf("%s/ca.key", tempCaDir),
		"-out", tempNodeDir,
		"-ip-addresses", "127.0.0.1",
		"-dns-names", "localhost",
		"-name", "renamed",
	}

	result := createNode.Run(args)
	assert.Equal(t, 0, result, "The 'create-node' operation should succeed with the --name flag")

	assert.FileExists(t, filepath.Join(tempNodeDir, "renamed.crt"), "Renamed certificate should exist")
	assert.FileExists(t, filepath.Join(tempNodeDir, "renamed.key"), "Renamed key should exist")
}

func TestCreateNodeCertificate_WithNameFlagWithoutOutput_ShouldCreateNamedCertificate(t *testing.T) {
	t.Parallel()

	cleanup, tempNodeDir, tempCaDir, _, _, createNode := setupCreateNodeTestEnvironment(t)
	defer cleanup()

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %s", err)
	}
	defer func(dir string) {
		err := os.Chdir(dir)
		if err != nil {
			t.Fatalf("Failed to change to orignal directory: %s", err)
		}
	}(originalDir)

	if err := os.Chdir(tempNodeDir); err != nil {
		t.Fatalf("Failed to change current directory: %s", err)
	}

	args := []string{
		"-ca-certificate", fmt.Sprintf("%s/ca.crt", tempCaDir),
		"-ca-key", fmt.Sprintf("%s/ca.key", tempCaDir),
		"-ip-addresses", "127.0.0.1",
		"-name", "renamed_without_output",
	}

	result := createNode.Run(args)
	assert.Equal(t, 0, result, "The 'create-node' operation should succeed with the --name flag")

	assert.FileExists(t, filepath.Join(tempNodeDir, "node1", "renamed_without_output.crt"), "Renamed certificate should exist")
	assert.FileExists(t, filepath.Join(tempNodeDir, "node1", "renamed_without_output.key"), "Renamed key should exist")
}

func TestCreateNodeCertificate_WithForceFlag_ShouldRegenerate(t *testing.T) {
	t.Parallel()

	cleanup, tempNodeDir, tempCaDir, _, _, createNode := setupCreateNodeTestEnvironment(t)
	defer cleanup()

	args := []string{
		"-ca-certificate", fmt.Sprintf("%s/ca.crt", tempCaDir),
		"-ca-key", fmt.Sprintf("%s/ca.key", tempCaDir),
		"-out", tempNodeDir,
		"-ip-addresses", "127.0.0.1",
		"-dns-names", "localhost",
	}

	result := createNode.Run(args)
	originalNodeCert, originalNodeKey := readAndDecodeCertificateAndKey(t, tempNodeDir, "node")

	updatedArgs := append(args, "-force")
	result = createNode.Run(updatedArgs)
	assert.Equal(t, 0, result, "The 'create-node' should override the existing certificate with the --force flag")

	newNodeCert, newNodeKey := readAndDecodeCertificateAndKey(t, tempNodeDir, "node")

	assert.NotEqual(t, originalNodeCert, newNodeCert, "The Node certificate should be different")
	assert.NotEqual(t, originalNodeKey, newNodeKey, "The Node key should be different")
}

func setupCreateNodeTestEnvironment(t *testing.T) (cleanupFunc func(), tempNodeDir, tempCaDir string, outputBuffer *bytes.Buffer, errorBuffer *bytes.Buffer, createNode *CreateNode) {
	var err error

	tempNodeDir, err = os.MkdirTemp(os.TempDir(), "node-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err)
	}

	tempCaDir, err = os.MkdirTemp(os.TempDir(), "ca-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err)
	}

	outputBuffer = new(bytes.Buffer)
	errorBuffer = new(bytes.Buffer)

	createNode = NewCreateNode(&cli.BasicUi{
		Writer:      outputBuffer,
		ErrorWriter: errorBuffer,
	})

	// We need to create a root CA file to be able to create a node certificate
	createCa := NewCreateCA(&cli.BasicUi{
		Writer:      new(bytes.Buffer),
		ErrorWriter: new(bytes.Buffer),
	})

	args := []string{"-out", tempCaDir}
	if result := createCa.Run(args); result != 0 {
		t.Fatalf("Expected 0, got %d", result)
	}

	cleanupFunc = func() {
		if err := os.RemoveAll(tempNodeDir); err != nil {
			t.Logf("Failed to remove temp node directory (%s): %s", tempNodeDir, err)
		}
		if err := os.RemoveAll(tempCaDir); err != nil {
			t.Logf("Failed to remove temp ca directory (%s): %s", tempCaDir, err)
		}
	}

	return cleanupFunc, tempNodeDir, tempCaDir, outputBuffer, errorBuffer, createNode
}
