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
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateNode struct {
	Ui cli.Ui
}

type CreateNodeArguments struct {
	CACertificatePath string `yaml:"ca-certificate"`
	CAKeyPath         string `yaml:"ca-key"`
	IPAddresses       string `yaml:"ip-addresses"`
	DNSNames          string `yaml:"dns-names"`
	Days              int    `yaml:"days"`
	OutputDir         string `yaml:"out"`
	CommonName        string `yaml:"common-name"`
	Force             bool   `yaml:"force"`
}

func readCertificateFromFile(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
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
	keyBytes, err := os.ReadFile(path)
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
			return nil, fmt.Errorf("invalid IP address: %s", tokens[i])
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
	flags.BoolVar(&config.Force, "force", false, "Force overwrite of existing files without prompting")

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

	// check if certificates already exist
	keyPath := path.Join(config.OutputDir, fmt.Sprintf("%s.key", outputBaseFileName))
	crtPath := path.Join(config.OutputDir, fmt.Sprintf("%s.crt", outputBaseFileName))

	if fileExists(keyPath, config.Force) {
		c.Ui.Error(ErrFileExists)
		return 1
	}

	if fileExists(crtPath, config.Force) {
		c.Ui.Error(ErrFileExists)
		return 1
	}

	/*default validity period*/
	years := 1
	days := 0

	if config.Days != 0 {
		days = config.Days
		years = 0
	}

	err = generateNodeCertificate(caCert, caKey, ips, dnsNames, years, days, outputDir, outputBaseFileName, config.CommonName, config.Force)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if isBoringEnabled() {
		c.Ui.Output(fmt.Sprintf("A node certificate & key file have been generated in the '%s' directory (FIPS mode enabled).", outputDir))
	} else {
		c.Ui.Output(fmt.Sprintf("A node certificate & key file have been generated in the '%s' directory.", outputDir))
	}

	return 0
}

func generateNodeCertificate(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, ips []net.IP, dnsNames []string, years int, days int, outputDir string, outputBaseFileName string, commonName string, force bool) error {
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

	err = writeCACertAndKey(outputDir, outputBaseFileName, certPem, privateKeyPem, force)

	return err
}

func (c *CreateNode) Help() string {
	var buffer bytes.Buffer

	w := tabwriter.NewWriter(&buffer, 0, 0, 2, ' ', 0) // 2 spaces minimum gap between columns

	fmt.Fprintln(w, "Usage: create_node [options]")
	fmt.Fprintln(w, "Generate a node/server TLS certificate to be used with EventStoreDB.")
	fmt.Fprintln(w, "Options:")

	writeHelpOption(w, "ca-certificate", "The path to the CA certificate file (default: ./ca/ca.crt).")
	writeHelpOption(w, "ca-key", "The path to the CA key file (default: ./ca/ca.key).")
	writeHelpOption(w, "days", "The validity period of the certificates in days (default: 1 year).")
	writeHelpOption(w, "out", "The output directory (default: ./nodeX where X is an auto-generated number).")
	writeHelpOption(w, "ip-addresses", "Comma-separated list of IP addresses of the node.")
	writeHelpOption(w, "dns-names", "Comma-separated list of DNS names of the node.")
	writeHelpOption(w, "common-name", "The certificate subject common name.")
	writeHelpOption(w, "force", forceOption)

	fmt.Fprintln(w, "\nAt least one IP address or DNS name needs to be specified.")

	w.Flush()

	return strings.TrimSpace(buffer.String())
}

func (c *CreateNode) Synopsis() string {
	return "Generate a node/server TLS certificate to be used with EventStoreDB"
}
