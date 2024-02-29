package certificates

import (
	"crypto/x509"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupTestEnvironmentForNodeTests(t *testing.T) (years int, days int, outputDirCa string, outputDirNode string, nodeCertFileName string, ipAddresses string, commonName string, dnsNames []string) {
	years = 1
	days = 0
	outputDirCa = "./ca"
	outputDirNode = "./node"
	nodeCertFileName = "node"
	ipAddresses = "127.0.0.1"
	commonName = "EventStoreDB"
	dnsNames = []string{"localhost"}

	cleanupDirsForTest(t, outputDirCa, outputDirNode)
	return
}

func TestGenerateNodeCertificate(t *testing.T) {

	t.Run("nominal-case", func(t *testing.T) {
		years, days, outputDirCa, outputDirNode, nodeCertFileName, ipAddresses, commonName, dnsNames := setupTestEnvironmentForNodeTests(t)

		caCertificate, caPrivateKey := generateAndAssertCACert(t, years, days, outputDirCa, false)
		ips, err := parseIPAddresses(ipAddresses)
		assert.NoError(t, err)

		certificateError := generateNodeCertificate(caCertificate, caPrivateKey, ips, dnsNames, years, days, outputDirNode, nodeCertFileName, commonName, false)
		assert.NoError(t, certificateError)

		nodeCertPath := path.Join(outputDirNode, nodeCertFileName+".crt")
		nodeKeyPath := path.Join(outputDirNode, nodeCertFileName+".key")
		assertFilesExist(t, nodeCertPath, nodeKeyPath)

		nodeCertificate, err := readCertificateFromFile(nodeCertPath)
		assert.NoError(t, err)

		// verify the subject
		assert.Equal(t, "CN=EventStoreDB", nodeCertificate.Subject.String())

		// verify the issuer
		assert.Equal(t, caCertificate.Issuer.String(), nodeCertificate.Issuer.String())

		// verify the EKUs
		assert.Equal(t, 2, len(nodeCertificate.ExtKeyUsage))
		assert.Equal(t, x509.ExtKeyUsageClientAuth, nodeCertificate.ExtKeyUsage[0])
		assert.Equal(t, x509.ExtKeyUsageServerAuth, nodeCertificate.ExtKeyUsage[1])
		assert.Equal(t, 0, len(nodeCertificate.UnknownExtKeyUsage))

		// verify the IP SANs
		assert.Equal(t, 1, len(nodeCertificate.IPAddresses))
		assert.Equal(t, "127.0.0.1", nodeCertificate.IPAddresses[0].String())

		// verify the DNS SANs
		assert.Equal(t, 1, len(nodeCertificate.DNSNames))
		assert.Equal(t, "localhost", nodeCertificate.DNSNames[0])
	})

	t.Run("force-flag", func(t *testing.T) {
		years, days, outputDirCa, outputDirNode, nodeCertFileName, ipAddresses, commonName, dnsNames := setupTestEnvironmentForNodeTests(t)

		caCertificate, caPrivateKey := generateAndAssertCACert(t, years, days, outputDirCa, false)
		ips, err := parseIPAddresses(ipAddresses)
		assert.NoError(t, err)

		nodeCertFilePath := path.Join(outputDirNode, nodeCertFileName+".crt")
		nodeKeyFilePath := path.Join(outputDirNode, nodeCertFileName+".key")

		generateNodeCertificate(caCertificate, caPrivateKey, ips, dnsNames, years, days, outputDirNode, nodeCertFileName, commonName, false)
		nodeCertFile, err := readCertificateFromFile(nodeCertFilePath)
		assert.NoError(t, err)
		nodeKeyFile, err := readRSAKeyFromFile(nodeKeyFilePath)
		assert.NoError(t, err)

		// try to generate again without force
		err = generateNodeCertificate(caCertificate, caPrivateKey, ips, dnsNames, years, days, outputDirNode, nodeCertFileName, commonName, false)
		assert.Error(t, err)
		nodeCertFileAfter, err := readCertificateFromFile(nodeCertFilePath)
		assert.NoError(t, err)
		nodeKeyFileAfter, err := readRSAKeyFromFile(nodeKeyFilePath)
		assert.NoError(t, err)
		assert.Equal(t, nodeCertFile, nodeCertFileAfter, "Expected node certificate to be the same")
		assert.Equal(t, nodeKeyFile, nodeKeyFileAfter, "Expected node key to be the same")

		// try to generate again with force
		err = generateNodeCertificate(caCertificate, caPrivateKey, ips, dnsNames, years, days, outputDirNode, nodeCertFileName, commonName, true)
		assert.NoError(t, err)
		nodeCertFileAfterWithForce, err := readCertificateFromFile(nodeCertFilePath)
		assert.NoError(t, err)
		nodeKeyFileAfterWithForce, err := readRSAKeyFromFile(nodeKeyFilePath)
		assert.NoError(t, err)
		assert.NotEqual(t, nodeCertFileAfter, nodeCertFileAfterWithForce, "Expected node certificate to be different")
		assert.NotEqual(t, nodeKeyFileAfter, nodeKeyFileAfterWithForce, "Expected node key key to be different")
	})
}
