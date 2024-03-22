package certificates

import (
	"bytes"
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateCertificates(t *testing.T) {
	t.Run("TestCreateCertificates_ValidConfigFile_ShouldSucceed", TestCreateCertificates_ValidConfigFile_ShouldSucceed)
	t.Run("TestCreateCertificates_ExistingCertificatesWithoutForceFlag_ShouldFail", TestCreateCertificates_ExistingCertificatesWithoutForceFlag_ShouldFail)
	t.Run("TestCreateCertificates_ForceFlagWithExistingCertificates_ShouldRegenerate", TestCreateCertificates_ForceFlagWithExistingCertificates_ShouldRegenerate)
	t.Run("TestCreateCertificates_ValidConfigWithCustomNames_ShouldCreateNamedCertificates", TestCreateCertificates_ValidConfigWithCustomNames_ShouldCreateNamedCertificates)
	t.Run("TestCreateCertificates_InvalidPathInConfig_ShouldFailWithError", TestCreateCertificates_InvalidPathInConfig_ShouldFailWithError)
}

func TestCreateCertificates_ValidConfigFile_ShouldSucceed(t *testing.T) {
	// Create certificates from a certs.yml file

	t.Parallel()

	cleanup, tempCertsDir, _, _, createCerts := setupCertificateTestEnvironment(t)
	defer cleanup()

	certsFileWithName := "certs.yml"

	// Create a certs.yml file
	createConfigFile(t, tempCertsDir, certsFileWithName, validCertificatesYaml, tempCertsDir)

	args := []string{
		"-config-file", filepath.Join(tempCertsDir, certsFileWithName),
	}

	result := createCerts.Run(args)
	assert.Equal(t, 0, result, "The create-certs command should succeed")

	assert.FileExists(t, filepath.Join(tempCertsDir, "root_ca", "ca.crt"), "Root CA certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "root_ca", "ca.key"), "Root CA key should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "intermediate_ca", "ca.crt"), "Intermediate certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "intermediate_ca", "ca.key"), "Intermediate certificate key should exist")

	nodes := []string{"node1", "node2", "node3"}
	for _, node := range nodes {
		assert.FileExists(t, filepath.Join(tempCertsDir, node, "node.crt"), fmt.Sprintf("%s certificate should exist", node))
		assert.FileExists(t, filepath.Join(tempCertsDir, node, "node.key"), fmt.Sprintf("%s certificate key should exist", node))
	}
}

func TestCreateCertificates_ExistingCertificatesWithoutForceFlag_ShouldFail(t *testing.T) {
	// Create certificates from config file and should fail because the certificates already exist
	// 1. Successfully create certificates from config file
	// 2. Run create-certs again without the force flag
	// 3. Expect an error suggesting that the certificates already exist and that the force flag should be used

	t.Parallel()

	cleanup, tempCertsDir, _, errorBuffer, createCerts := setupCertificateTestEnvironment(t)
	defer cleanup()

	createConfigFile(t, tempCertsDir, "certs.yml", validCertificatesYaml, tempCertsDir)

	args := []string{
		"-config-file", tempCertsDir + "/certs.yml",
	}

	result := createCerts.Run(args)
	assert.Equal(t, 0, result, "The create-certs command should succeed the first time it is run since the certificates do not exist")

	assert.FileExists(t, filepath.Join(tempCertsDir, "root_ca", "ca.crt"), "Root CA certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "root_ca", "ca.key"), "Root CA key should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "intermediate_ca", "ca.crt"), "Intermediate certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "intermediate_ca", "ca.key"), "Intermediate certificate key should exist")

	nodes := []string{"node1", "node2", "node3"}
	for _, node := range nodes {
		assert.FileExists(t, filepath.Join(tempCertsDir, node, "node.crt"), fmt.Sprintf("%s certificate should exist", node))
		assert.FileExists(t, filepath.Join(tempCertsDir, node, "node.key"), fmt.Sprintf("%s certificate key should exist", node))
	}

	// Try to generate the certificates again and expect and error
	result = createCerts.Run(args)
	assert.Equal(t, 1, result, "The create-certs command should fail the second time it is run since the certificates already exist")
	errors := extractErrors(errorBuffer.String())

	assert.Equal(t, 1, len(errors), "Expected 1 error")
	assert.Equal(t, "existing files would be overwritten. Use -force to proceed", errors[0])
}

func TestCreateCertificates_ForceFlagWithExistingCertificates_ShouldRegenerate(t *testing.T) {
	// Create certificates from a certs.yml file with the force flag
	// Expect all certificates to be regenerated and different from the original ones

	t.Parallel()

	cleanup, tempCertsDir, _, _, createCerts := setupCertificateTestEnvironment(t)
	defer cleanup()

	certsFileWithName := "certs.yml"

	// Create a certs.yml file
	createConfigFile(t, tempCertsDir, certsFileWithName, validCertificatesYaml, tempCertsDir)

	args := []string{
		"-config-file", filepath.Join(tempCertsDir, certsFileWithName),
	}

	result := createCerts.Run(args)
	assert.Equal(t, 0, result, "The create-certs command should succeed the first time it is run since the certificates do not exist")

	assert.FileExists(t, filepath.Join(tempCertsDir, "root_ca", "ca.crt"), "Root CA certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "root_ca", "ca.key"), "Root CA key should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "intermediate_ca", "ca.crt"), "Intermediate certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "intermediate_ca", "ca.key"), "Intermediate certificate key should exist")

	nodes := []string{"node1", "node2", "node3"}
	for _, node := range nodes {
		assert.FileExists(t, filepath.Join(tempCertsDir, node, "node.crt"), fmt.Sprintf("%s certificate should exist", node))
		assert.FileExists(t, filepath.Join(tempCertsDir, node, "node.key"), fmt.Sprintf("%s certificate key should exist", node))
	}

	// Read the content of the key and crt files generated from the config file
	originalCaCert, originalKeyCert := readAndDecodeCertificateAndKey(t, filepath.Join(tempCertsDir, "root_ca"), "ca")
	originalIntermediateCaCert, originalIntermediateKeyCert := readAndDecodeCertificateAndKey(t, filepath.Join(tempCertsDir, "intermediate_ca"), "ca")

	originalCerts := make(map[string][2]interface{})

	for _, node := range nodes {
		originalCaCert, originalKeyCert := readAndDecodeCertificateAndKey(t, filepath.Join(tempCertsDir, node), "node")
		originalCerts[node] = [2]interface{}{originalCaCert, originalKeyCert}
	}

	args = []string{
		"-config-file", filepath.Join(tempCertsDir, certsFileWithName),
		"-force",
	}

	result = createCerts.Run(args)
	assert.Equal(t, 0, result, "The create-certs command should succeed with the force flag and "+
		"override the existing certificates defined in the config file")

	newRootCaCert, newRootCaKey := readAndDecodeCertificateAndKey(t, filepath.Join(tempCertsDir, "root_ca"), "ca")
	newIntermediateCaCert, newIntermediateKeyCert := readAndDecodeCertificateAndKey(t, filepath.Join(tempCertsDir, "intermediate_ca"), "ca")

	assert.NotEqual(t, originalCaCert, newRootCaCert, "Root CA certificate should be regenerated")
	assert.NotEqual(t, originalKeyCert, newRootCaKey, "Root CA key should be regenerated")

	assert.NotEqual(t, originalIntermediateCaCert, newIntermediateCaCert, "Intermediate CA certificate should be regenerated")
	assert.NotEqual(t, originalIntermediateKeyCert, newIntermediateKeyCert, "Intermediate CA key should be regenerated")

	for _, node := range nodes {
		newCAHash, newKeyHash := readAndDecodeCertificateAndKey(t, filepath.Join(tempCertsDir, node), "node")
		assert.NotEqual(t, originalCerts[node][0], newCAHash, fmt.Sprintf("%s certificate should be regenerated", node))
		assert.NotEqual(t, originalCerts[node][1], newKeyHash, fmt.Sprintf("%s certificate key should be regenerated", node))
	}
}

func TestCreateCertificates_ValidConfigWithCustomNames_ShouldCreateNamedCertificates(t *testing.T) {
	// Create certificates from a certs.yml file with the name parameter
	// Expect all certificates to be named with the name parameter

	t.Parallel()

	cleanup, tempCertsDir, _, _, createCerts := setupCertificateTestEnvironment(t)
	defer cleanup()

	certsFileName := "certs-with-name.yml"

	createConfigFile(t, tempCertsDir, certsFileName, certificatesYamlWithOverrideName, tempCertsDir)

	args := []string{
		"-config-file", filepath.Join(tempCertsDir, certsFileName),
	}

	result := createCerts.Run(args)
	assert.Equal(t, 0, result, "The create-certs command should create certificates with custom names")

	assert.FileExists(t, filepath.Join(tempCertsDir, "custom_root", "custom_root.crt"), "Root CA certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "custom_root", "custom_root.key"), "Root CA key should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "custom_intermediate", "custom_intermediate.crt"), "Intermediate certificate should exist")
	assert.FileExists(t, filepath.Join(tempCertsDir, "custom_intermediate", "custom_intermediate.key"), "Intermediate certificate key should exist")

	nodes := []string{"custom_node1", "custom_node2", "custom_node3"}
	for _, node := range nodes {
		assert.FileExists(t, filepath.Join(tempCertsDir, node, fmt.Sprintf("%s.crt", node)), fmt.Sprintf("%s certificate should exist", node))
		assert.FileExists(t, filepath.Join(tempCertsDir, node, fmt.Sprintf("%s.key", node)), fmt.Sprintf("%s certificate key should exist", node))
	}
}

func TestCreateCertificates_InvalidPathInConfig_ShouldFailWithError(t *testing.T) {
	// An invalid path is defined at ca-certificate in the config.
	// The intermediate certificate uses an invalid path for the root CA certificate.
	// This should result in an error suggesting that ca.crt is not found.

	t.Parallel()

	cleanup, tempCertsDir, _, errorBuffer, createCerts := setupCertificateTestEnvironment(t)
	defer cleanup()

	certsFileName := "certs.yml"

	createConfigFile(t, tempCertsDir, certsFileName, certificatesYamlWithInvalidPath, tempCertsDir)

	args := []string{
		"-config-file", filepath.Join(tempCertsDir, certsFileName),
	}

	result := createCerts.Run(args)
	assert.Equal(t, 1, result, "The create-certs command should fail with code 1 when an invalid path is defined in the config")

	errors := extractErrors(errorBuffer.String())

	assert.Equal(t, 1, len(errors), "Expected 1 error")

	assert.Contains(t, errors[0], "error reading file")
	assert.Contains(t, errors[0], filepath.ToSlash(fmt.Sprintf("%s/invalid_root_ca/ca.crt", tempCertsDir)))

	// The root CA will be created
	assert.DirExists(t, filepath.Join(tempCertsDir, "root_ca"))

	// Intermediate and node1 will not be created
	assert.NoDirExists(t, filepath.Join(tempCertsDir, "intermediate_ca"), "Intermediate certificate should not exist")
	assert.NoDirExists(t, filepath.Join(tempCertsDir, "node1"), "Intermediate certificate key should not exist")
}

// Valid certificate file
var validCertificatesYaml = `certificates:
  ca-certs:
    - out: "./root_ca"
    - out: "./intermediate_ca"
      ca-certificate: "./root_ca/ca.crt"
      ca-key: "./root_ca/ca.key"
      days: 5
  node-certs:
    - out: "./node1"
      ca-certificate: "./intermediate_ca/ca.crt"
      ca-key: "./intermediate_ca/ca.key"
      ip-addresses: "127.0.0.1,172.20.240.1"
      dns-names: "localhost,eventstore-node1.localhost.com"
    - out: "./node2"
      ca-certificate: "./intermediate_ca/ca.crt"
      ca-key: "./intermediate_ca/ca.key"
      ip-addresses: "127.0.0.2,172.20.240.2"
      dns-names: "localhost,eventstore-node2.localhost.com"
    - out: "./node3"
      ca-certificate: "./intermediate_ca/ca.crt"
      ca-key: "./intermediate_ca/ca.key"
      ip-addresses: "127.0.0.3,172.20.240.3"
      dns-names: "localhost,eventstore-node2.localhost.com"`

// Invalid path defined at ca-certificate in the config
var certificatesYamlWithInvalidPath = `certificates:
  ca-certs:
    - out: "./root_ca"
    - out: "./intermediate_ca"
      ca-certificate: "./invalid_root_ca/ca.crt"
      ca-key: "./root_ca/ca.key"
      days: 5
  node-certs:
    - out: "./node1"
      ca-certificate: "./intermediate_ca/ca.crt"
      ca-key: "./intermediate_ca/ca.key"
      ip-addresses: "127.0.0.1,172.20.240.1"
      dns-names: "localhost,eventstore-node1.localhost.com"`

// Each certificate have a name parameter
var certificatesYamlWithOverrideName = `certificates:
  ca-certs:
    - out: "./custom_root"
      name: "custom_root"
    - out: "./custom_intermediate"
      name: "custom_intermediate"
      ca-certificate: "./custom_root/custom_root.crt"
      ca-key: "./custom_root/custom_root.key"
      days: 5
  node-certs:
    - out: "./custom_node1"
      name: "custom_node1"
      ca-certificate: "./custom_intermediate/custom_intermediate.crt"
      ca-key: "./custom_intermediate/custom_intermediate.key"
      ip-addresses: "127.0.0.1,172.20.240.1"
      dns-names: "localhost,eventstore-node1.localhost.com"
    - out: "./custom_node2"
      name: "custom_node2"
      ca-certificate: "./custom_intermediate/custom_intermediate.crt"
      ca-key: "./custom_intermediate/custom_intermediate.key"
      ip-addresses: "127.0.0.2,172.20.240.2"
      dns-names: "localhost,eventstore-node2.localhost.com"
    - out: "./custom_node3"
      name: "custom_node3"
      ca-certificate: "./custom_intermediate/custom_intermediate.crt"
      ca-key: "./custom_intermediate/custom_intermediate.key"
      ip-addresses: "127.0.0.3,172.20.240.3"
      dns-names: "localhost,eventstore-node2.localhost.com"`

func setupCertificateTestEnvironment(t *testing.T) (cleanupFunc func(), tempCertsDir string, outputBuffer *bytes.Buffer, errorBuffer *bytes.Buffer, createCerts *CreateCertificates) {
	tempCertsDir, err := os.MkdirTemp(os.TempDir(), "certs-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err)
	}

	outputBuffer = new(bytes.Buffer)
	errorBuffer = new(bytes.Buffer)

	createCerts = NewCreateCerts(&cli.BasicUi{
		Writer:      outputBuffer,
		ErrorWriter: errorBuffer,
	})

	cleanupFunc = func() {
		if err := os.RemoveAll(tempCertsDir); err != nil {
			t.Logf("Failed to remove temp directory (%s): %s", tempCertsDir, err)
		}
	}

	return cleanupFunc, tempCertsDir, outputBuffer, errorBuffer, createCerts
}

func createConfigFile(t *testing.T, dirPath string, fileName string, content string, newParentDir string) {
	updatedContent := strings.ReplaceAll(content, "./", fmt.Sprintf("%s/", filepath.ToSlash(newParentDir)))

	filePath := filepath.Join(dirPath, fileName)

	// Create the directory if it does not exist
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			t.Errorf("Error creating directory: %s", err)
		}
	}

	f, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			t.Error(err)
		}
	}(f)

	_, err = f.WriteString(updatedContent)
	if err != nil {
		panic(err)
	}
}
