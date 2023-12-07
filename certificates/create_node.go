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
	"strconv"
	"strings"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateNode struct {
	Ui     cli.Ui
	Flags  *flag.FlagSet
	Config CreateNodeArguments
}

type CreateNodeArguments struct {
	CACertificatePath string `yaml:"ca-certificate"`
	CAKeyPath         string `yaml:"ca-key"`
	IPAddresses       string `yaml:"ip-addresses"`
	DNSNames          string `yaml:"dns-names"`
	Days              int    `yaml:"days"`
	OutputDir         string `yaml:"out"`
	CommonName        string `yaml:"common-name"`
	Name              string `yaml:"name"`
	Force             bool   `yaml:"force"`
}

func NewCreateNode(ui cli.Ui) *CreateNode {
	c := &CreateNode{Ui: ui}

	c.Flags = flag.NewFlagSet("create_node", flag.ContinueOnError)
	c.Flags.StringVar(&c.Config.CACertificatePath, "ca-certificate", "./ca/ca.crt", CaPathFlagUsage)
	c.Flags.StringVar(&c.Config.CommonName, "common-name", "eventstoredb-node", "the certificate subject common name")
	c.Flags.StringVar(&c.Config.CAKeyPath, "ca-key", "./ca/ca.key", CaKeyFlagUsage)
	c.Flags.StringVar(&c.Config.IPAddresses, "ip-addresses", "", "comma-separated list of IP addresses of the node")
	c.Flags.StringVar(&c.Config.DNSNames, "dns-names", "", "comma-separated list of DNS names of the node")
	c.Flags.IntVar(&c.Config.Days, "days", 0, DayFlagUsage)
	c.Flags.StringVar(&c.Config.OutputDir, "out", "", OutDirFlagUsage)
	c.Flags.StringVar(&c.Config.Name, "name", "node", NameFlagUsage)
	c.Flags.BoolVar(&c.Config.Force, "force", false, ForceFlagUsage)
	return c
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
	if err := c.Flags.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	validationErrors := new(multierror.Error)
	if len(c.Config.CACertificatePath) == 0 {
		_ = multierror.Append(validationErrors, errors.New("ca-certificate is a required field"))
	}

	if len(c.Config.CAKeyPath) == 0 {
		_ = multierror.Append(validationErrors, errors.New("ca-key is a required field"))
	}

	if len(c.Config.IPAddresses) == 0 && len(c.Config.DNSNames) == 0 {
		_ = multierror.Append(validationErrors, errors.New("at least one IP address or DNS name needs to be specified with --ip-addresses or --dns-names"))
	}

	if c.Config.Days < 0 {
		_ = multierror.Append(validationErrors, errors.New("days must be positive"))
	}

	if validationErrors.ErrorOrNil() != nil {
		c.Ui.Error(validationErrors.Error())
		return 1
	}

	caCert, err := readCertificateFromFile(c.Config.CACertificatePath)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	caKey, err := readRSAKeyFromFile(c.Config.CAKeyPath)
	if err != nil {
		err := fmt.Errorf("error: %s. please note that only RSA keys are currently supported", err.Error())
		c.Ui.Error(err.Error())
		return 1
	}

	ips, err := parseIPAddresses(c.Config.IPAddresses)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	dnsNames, err := parseDNSNames(c.Config.DNSNames)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	outputDir := c.Config.OutputDir
	outputBaseFileName := c.Config.Name

	if len(outputDir) == 0 {
		outputDir, err = getOutputDirectory()
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}
		outputBaseFileName = outputDir
	}

	certErr := checkCertificatesLocationWithForce(outputDir, outputBaseFileName, c.Config.Force)
	if certErr != nil {
		c.Ui.Error(certErr.Error())
		return 1
	}

	/*default validity period*/
	years := 1
	days := 0

	if c.Config.Days != 0 {
		days = c.Config.Days
		years = 0
	}

	err = generateNodeCertificate(caCert, caKey, ips, dnsNames, years, days, outputDir, outputBaseFileName, c.Config.CommonName, c.Config.Force)
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

func generateNodeCertificate(
	caCert *x509.Certificate,
	caPrivateKey *rsa.PrivateKey,
	ips []net.IP,
	dnsNames []string,
	years int,
	days int,
	outputDir string,
	outputBaseFileName string,
	commonName string,
	force bool,
) error {
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
	err = pem.Encode(privateKeyPem, &pem.Block{
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

	err = writeCertAndKey(outputDir, outputBaseFileName, certPem, privateKeyPem, force)

	return err
}

func (c *CreateNode) Help() string {
	var helpText bytes.Buffer
	c.Flags.SetOutput(&helpText)
	c.Flags.PrintDefaults()
	return helpText.String()
}

func (c *CreateNode) Synopsis() string {
	return "Generate a node/server TLS certificate to be used with EventStoreDB"
}
