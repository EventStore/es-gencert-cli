package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	Years            = 1
	Days             = 0
	OutputDirCA      = "./ca"
	OutputDirNode    = "./node"
	NodeCertFileName = "node"
	IPAddresses      = "127.0.0.1"
	CommonName       = "EventStoreDB"
)

var DnsNames = []string{"localhost"}

func cleanup() {
	os.RemoveAll(OutputDirCA)
	os.RemoveAll(OutputDirNode)
}

func assertFilesExist(t *testing.T, files ...string) {
	for _, file := range files {
		_, err := os.Stat(file)
		assert.False(t, os.IsNotExist(err))
	}
}

func generateAndAssertCACert(t *testing.T, forceFlag bool) (*x509.Certificate, *rsa.PrivateKey) {
	certificateError := generateCACertificate(Years, Days, OutputDirCA, nil, nil, forceFlag)
	assert.NoError(t, certificateError)

	certFilePath := path.Join(OutputDirCA, "ca.crt")
	keyFilePath := path.Join(OutputDirCA, "ca.key")
	assertFilesExist(t, certFilePath, keyFilePath)

	caCertificate, err := readCertificateFromFile(certFilePath)
	assert.NoError(t, err)
	caPrivateKey, err := readRSAKeyFromFile(keyFilePath)
	assert.NoError(t, err)

	return caCertificate, caPrivateKey
}

func TestGenerateNodeCertificate(t *testing.T) {

	t.Run("nominal-case", func(t *testing.T) {
		cleanup()

		caCertificate, caPrivateKey := generateAndAssertCACert(t, false)
		ips, err := parseIPAddresses(IPAddresses)
		assert.NoError(t, err)

		certificateError := generateNodeCertificate(caCertificate, caPrivateKey, ips, DnsNames, Years, Days, OutputDirNode, NodeCertFileName, CommonName, false)
		assert.NoError(t, certificateError)

		nodeCertPath := path.Join(OutputDirNode, NodeCertFileName+".crt")
		nodeKeyPath := path.Join(OutputDirNode, NodeCertFileName+".key")
		assertFilesExist(t, nodeCertPath, nodeKeyPath)

		cleanup()
	})

	t.Run("force-flag", func(t *testing.T) {
		cleanup()

		caCertificate, caPrivateKey := generateAndAssertCACert(t, false)
		ips, err := parseIPAddresses(IPAddresses)
		assert.NoError(t, err)

		nodeCertFilePath := path.Join(OutputDirNode, NodeCertFileName+".crt")
		nodeKeyFilePath := path.Join(OutputDirNode, NodeCertFileName+".key")

		generateNodeCertificate(caCertificate, caPrivateKey, ips, DnsNames, Years, Days, OutputDirNode, NodeCertFileName, CommonName, false)
		nodeCertFile, err := readCertificateFromFile(nodeCertFilePath)
		assert.NoError(t, err)
		nodeKeyFile, err := readRSAKeyFromFile(nodeKeyFilePath)
		assert.NoError(t, err)

		// try to generate again without force
		err = generateNodeCertificate(caCertificate, caPrivateKey, ips, DnsNames, Years, Days, OutputDirNode, NodeCertFileName, CommonName, false)
		assert.Error(t, err)
		nodeCertFileAfter, err := readCertificateFromFile(nodeCertFilePath)
		assert.NoError(t, err)
		nodeKeyFileAfter, err := readRSAKeyFromFile(nodeKeyFilePath)
		assert.NoError(t, err)
		assert.Equal(t, nodeCertFile, nodeCertFileAfter, "Expected node certificate to be the same")
		assert.Equal(t, nodeKeyFile, nodeKeyFileAfter, "Expected node key to be the same")

		// try to generate again with force
		err = generateNodeCertificate(caCertificate, caPrivateKey, ips, DnsNames, Years, Days, OutputDirNode, NodeCertFileName, CommonName, true)
		assert.NoError(t, err)
		nodeCertFileAfterWithForce, err := readCertificateFromFile(nodeCertFilePath)
		assert.NoError(t, err)
		nodeKeyFileAfterWithForce, err := readRSAKeyFromFile(nodeKeyFilePath)
		assert.NoError(t, err)
		assert.NotEqual(t, nodeCertFileAfter, nodeCertFileAfterWithForce, "Expected node certificate to be different")
		assert.NotEqual(t, nodeKeyFileAfter, nodeKeyFileAfterWithForce, "Expected node key key to be different")

		cleanup()
	})
}
