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
	"path"
	"strings"
	"text/tabwriter"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateUser struct {
	Ui cli.Ui
}

type CreateUserArguments struct {
	Username          string `yaml:"username"`
	CACertificatePath string `yaml:"ca-certificate"`
	CAKeyPath         string `yaml:"ca-key"`
	Days              int    `yaml:"days"`
	OutputDir         string `yaml:"out"`
	Force             bool   `yaml:"force"`
}

func (c *CreateUser) Run(args []string) int {
	var config CreateUserArguments

	flags := flag.NewFlagSet("create_user", flag.ContinueOnError)
	flags.Usage = func() { c.Ui.Info(c.Help()) }
	flags.StringVar(&config.Username, "username", "", "the EventStoreDB user")
	flags.StringVar(&config.CACertificatePath, "ca-certificate", "./ca/ca.crt", "the path to the CA certificate file")
	flags.StringVar(&config.CAKeyPath, "ca-key", "./ca/ca.key", "the path to the CA key file")
	flags.IntVar(&config.Days, "days", 0, "the validity period of the certificate in days")
	flags.StringVar(&config.OutputDir, "out", "", "The output directory")
	flags.BoolVar(&config.Force, "force", false, forceOption)

	if err := flags.Parse(args); err != nil {
		return 1
	}

	validationErrors := new(multierror.Error)

	if len(config.Username) == 0 {
		multierror.Append(validationErrors, errors.New("username is a required field"))
	}

	if len(config.CACertificatePath) == 0 {
		multierror.Append(validationErrors, errors.New("ca-certificate is a required field"))
	}

	if len(config.CAKeyPath) == 0 {
		multierror.Append(validationErrors, errors.New("ca-key is a required field"))
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

	outputDir := config.OutputDir
	outputBaseFileName := "user-" + config.Username

	if len(outputDir) == 0 {
		outputDir = outputBaseFileName
	}

	// check if user certificates already exist
	if fileExists(path.Join(outputDir, outputBaseFileName+".crt"), config.Force) {
		c.Ui.Error(ErrFileExists)
		return 1
	}

	if fileExists(path.Join(outputDir, outputBaseFileName+".key"), config.Force) {
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

	err = generateUserCertificate(config.Username, outputBaseFileName, caCert, caKey, years, days, outputDir, config.Force)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if isBoringEnabled() {
		c.Ui.Output(fmt.Sprintf("A user certificate & key file have been generated in the '%s' directory (FIPS mode enabled).", outputDir))
	} else {
		c.Ui.Output(fmt.Sprintf("A user certificate & key file have been generated in the '%s' directory.", outputDir))
	}

	return 0
}

func generateUserCertificate(username string, outputBaseFileName string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, years int, days int, outputDir string, force bool) error {
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
			CommonName: username,
		},
		IsCA:                  false,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(years, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

	err = writeCertAndKey(outputDir, outputBaseFileName, certPem, privateKeyPem, force)

	return err
}

func (c *CreateUser) Help() string {
	var buffer bytes.Buffer

	w := tabwriter.NewWriter(&buffer, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "Usage: create_user [options]")
	fmt.Fprintln(w, c.Synopsis())
	fmt.Fprintln(w, "Options:")

	writeHelpOption(w, "username", "The name of the EventStoreDB user to generate a certificate for.")
	writeHelpOption(w, "ca-certificate", "The path to the CA certificate file (default: ./ca/ca.crt).")
	writeHelpOption(w, "ca-key", "The path to the CA key file (default: ./ca/ca.key).")
	writeHelpOption(w, "days", "The validity period of the certificates in days (default: 1 year).")
	writeHelpOption(w, "out", "The output directory (default: ./user-<username>).")
	writeHelpOption(w, "force", forceOption)

	w.Flush()

	return strings.TrimSpace(buffer.String())
}

func (c *CreateUser) Synopsis() string {
	return "Generate a user TLS certificate to be used with EventStoreDB clients"
}
