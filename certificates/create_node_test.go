package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateNodeCertificate(t *testing.T) {
	t.Run("nominal-case", func(t *testing.T) {
		years := 1
		days := 0
		outputDirCA := "./ca"
		outputDirNode := "./node"
		var caCert *x509.Certificate
		var caKey *rsa.PrivateKey
		var nodeCertFileName = "node"
		var ipAddresses = "127.0.0.1"
		var dnsNames = []string{"localhost"}
		var commonName = "EventStoreDB"

		// Clean up from previous runs
		os.RemoveAll(outputDirCA)
		os.RemoveAll(outputDirNode)

		certificateError := generateCACertificate(years, days, outputDirCA, caCert, caKey)

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

		ips, err := parseIPAddresses(ipAddresses)
		assert.NoError(t, err)

		certificateError = generateNodeCertificate(caCertificate, caPrivateKey, ips, dnsNames, years, days, outputDirNode, nodeCertFileName, commonName)

		nodeCertPath := path.Join(outputDirNode, "node.crt")
		nodeKeyPath := path.Join(outputDirNode, "node.key")

		_, nodeCertPathError := os.Stat(nodeCertPath)
		_, nodeKeyPathError := os.Stat(nodeKeyPath)

		assert.NoError(t, certificateError)
		assert.False(t, os.IsNotExist(nodeCertPathError))
		assert.False(t, os.IsNotExist(nodeKeyPathError))

		// Clean up
		os.RemoveAll(outputDirCA)
		os.RemoveAll(outputDirNode)
	})
}
