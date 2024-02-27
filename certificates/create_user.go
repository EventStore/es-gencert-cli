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
	"os"
	"path"
	"strconv"
	"strings"
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
}

func getUserOutputDirectory(username string) (string, error) {
	dir := "user-" + username
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return dir, nil
	}

	for i := 1; i <= 100; i++ {
		dir = "user-" + username + strconv.Itoa(i)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return dir, nil
		}
	}

	return "", fmt.Errorf("could not obtain a proper name for output directory")
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
		outputDir, err = getUserOutputDirectory(config.Username)
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

	err = generateUserCertificate(config.Username, caCert, caKey, years, days, outputDir, outputBaseFileName)
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

func generateUserCertificate(username string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, years int, days int, outputDir string, outputBaseFileName string) error {
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
	err = os.WriteFile(path.Join(outputDir, certFile), certPem.Bytes(), 0444)
	if err != nil {
		return fmt.Errorf("error writing certificate to %s: %s", certFile, err.Error())
	}

	keyFile := fmt.Sprintf("%s.key", outputBaseFileName)
	err = os.WriteFile(path.Join(outputDir, keyFile), privateKeyPem.Bytes(), 0400)
	if err != nil {
		return fmt.Errorf("error writing private key to %s: %s", keyFile, err.Error())
	}

	return nil

}
func (c *CreateUser) Help() string {
	helpText := `
Usage: create_user [options]
  Generate a user TLS certificate to be used with EventStoreDB clients
Options:
  -username                   The name of the EventStoreDB user
  -ca-certificate             The path to the CA certificate file (default: ./ca/ca.crt)
  -ca-key                     The path to the CA key file (default: ./ca/ca.key)
  -days                       The validity period of the certificates in days (default: 1 year)
  -out                        The output directory (default: ./user-<username>)
`
	return strings.TrimSpace(helpText)
}

func (c *CreateUser) Synopsis() string {
	return "Generate a user TLS certificate to be used with EventStoreDB clients"
}
