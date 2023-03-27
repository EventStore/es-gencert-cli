package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateNode struct {
	Ui cli.Ui
}

type CreateNodeArguments struct {
	CACertificatePath string
	CAKeyPath         string
	IPAddresses       string
	DNSNames          string
	Days              int
	OutputDir         string
	CommonName        string
}

func readCertificateFromFile(path string) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err.Error())
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM data from file: %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate from ASN.1 DER data in file: %s", path)
	}
	return cert, nil
}

func readRSAKeyFromFile(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err.Error())
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM data from file: %s", path)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA key from ASN.1 DER data in file: %s", path)
	}
	return key, nil
}

func parseIPAddresses(ipAddresses string) ([]net.IP, error) {
	if len(ipAddresses) == 0 {
		return []net.IP{}, nil
	}
	ips := make([]net.IP, 0)
	tokens := strings.Split(ipAddresses, ",")
	for i := range tokens {
		ip := net.ParseIP(tokens[i])
		if ip == nil {
			return nil, fmt.Errorf("Invalid IP address: %s", tokens[i])
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func parseDNSNames(dnsNames string) ([]string, error) {
	if len(dnsNames) == 0 {
		return []string{}, nil
	}
	dns := strings.Split(dnsNames, ",")
	return dns, nil
}

func getOutputDirectory() (string, error) {
	for i := 1; i <= 100; i++ {
		dir := "node" + strconv.Itoa(i)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("could not obtain a proper name for output directory")
}

func (c *CreateNode) Run(args []string) int {
	var config CreateNodeArguments

	flags := flag.NewFlagSet("create_node", flag.ContinueOnError)
	flags.Usage = func() { c.Ui.Info(c.Help()) }
	flags.StringVar(&config.CACertificatePath, "ca-certificate", "./ca/ca.crt", "the path to the CA certificate file")
	flags.StringVar(&config.CommonName, "common-name", "eventstoredb-node", "the certificate subject common name")
	flags.StringVar(&config.CAKeyPath, "ca-key", "./ca/ca.key", "the path to the CA key file")
	flags.StringVar(&config.IPAddresses, "ip-addresses", "", "comma-separated list of IP addresses of the node")
	flags.StringVar(&config.DNSNames, "dns-names", "", "comma-separated list of DNS names of the node")
	flags.IntVar(&config.Days, "days", 0, "the validity period of the certificate in days")
	flags.StringVar(&config.OutputDir, "out", "", "The output directory")

	if err := flags.Parse(args); err != nil {
		return 1
	}

	validationErrors := new(multierror.Error)
	if len(config.CACertificatePath) == 0 {
		multierror.Append(validationErrors, errors.New("ca-certificate is a required field"))
	}

	if len(config.CAKeyPath) == 0 {
		multierror.Append(validationErrors, errors.New("ca-key is a required field"))
	}

	if len(config.IPAddresses) == 0 && len(config.DNSNames) == 0 {
		multierror.Append(validationErrors, errors.New("at least one IP address or DNS name needs to be specified with --ip-addresses or --dns-names"))
	}

	if config.Days < 0 {
		multierror.Append(validationErrors, errors.New("days must be positive"))
	}

	if validationErrors.ErrorOrNil() != nil {
		c.Ui.Error(validationErrors.Error())
		return 1
	}

	caCert, err := readCertificateFromFile(config.CACertificatePath)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	caKey, err := readRSAKeyFromFile(config.CAKeyPath)
	if err != nil {
		err := fmt.Errorf("error: %s. please note that only RSA keys are currently supported", err.Error())
		c.Ui.Error(err.Error())
		return 1
	}

	ips, err := parseIPAddresses(config.IPAddresses)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	dnsNames, err := parseDNSNames(config.DNSNames)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	outputDir := config.OutputDir
	outputBaseFileName := "node"

	if len(outputDir) == 0 {
		outputDir, err = getOutputDirectory()
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}
		outputBaseFileName = outputDir
	}

	/*default validity period*/
	years := 1
	days := 0

	if config.Days != 0 {
		days = config.Days
		years = 0
	}

	err = generateNodeCertificate(caCert, caKey, ips, dnsNames, years, days, outputDir, outputBaseFileName, config.CommonName)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	c.Ui.Output(fmt.Sprintf("A node certificate & key file have been generated in the '%s' directory.", outputDir))
	return 0
}

func generateNodeCertificate(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, ips []net.IP, dnsNames []string, years int, days int, outputDir string, outputBaseFileName string, commonName string) error {
	serialNumber, err := generateSerialNumber(128)
	if err != nil {
		return fmt.Errorf("could not generate 128-bit serial number: %s", err.Error())
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySize)
	if err != nil {
		return fmt.Errorf("could not generate RSA private key: %s", err.Error())
	}

	subjectKeyID := generateKeyIDFromRSAPublicKey(privateKey.N, privateKey.E)
	authorityKeyID := generateKeyIDFromRSAPublicKey(caPrivateKey.N, caPrivateKey.E)

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		IsCA:                  false,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(years, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:           ips,
		DNSNames:              dnsNames,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        authorityKeyID,
	}

	privateKeyPem := new(bytes.Buffer)
	pem.Encode(privateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return fmt.Errorf("could not encode private key to PEM format: %s", err.Error())
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return fmt.Errorf("could not generate certificate: %s", err.Error())
	}

	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return fmt.Errorf("could not encode certificate to PEM format: %s", err.Error())
	}

	err = os.Mkdir(outputDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("could not create directory %s: %s", outputDir, err.Error())
		}
		if os.IsExist(err) {
			return fmt.Errorf("output directory: %s already exists. please delete it and try again", outputDir)
		}
	}

	certFile := fmt.Sprintf("%s.crt", outputBaseFileName)
	err = ioutil.WriteFile(path.Join(outputDir, certFile), certPem.Bytes(), 0444)
	if err != nil {
		return fmt.Errorf("error writing certificate to %s: %s", certFile, err.Error())
	}

	keyFile := fmt.Sprintf("%s.key", outputBaseFileName)
	err = ioutil.WriteFile(path.Join(outputDir, keyFile), privateKeyPem.Bytes(), 0400)
	if err != nil {
		return fmt.Errorf("error writing private key to %s: %s", keyFile, err.Error())
	}

	return nil

}
func (c *CreateNode) Help() string {
	helpText := `
Usage: create_node [options]
  Generate a node/server TLS certificate to be used with EventStoreDB
Options:
  -ca-certificate             The path to the CA certificate file (default: ./ca/ca.crt)
  -ca-key                     The path to the CA key file (default: ./ca/ca.key)
  -days                       The validity period of the certificates in days (default: 1 year)
  -out                        The output directory (default: ./nodeX where X is an auto-generated number)
  -ip-addresses               Comma-separated list of IP addresses of the node
  -dns-names                  Comma-separated list of DNS names of the node

  At least one IP address or DNS name needs to be specified
`
	return strings.TrimSpace(helpText)
}

func (c *CreateNode) Synopsis() string {
	return "Generate a node/server TLS certificate to be used with EventStoreDB"
}
