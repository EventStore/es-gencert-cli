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
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateCA struct {
	Ui cli.Ui
}

type CreateCAArguments struct {
	Days              int    `yaml:"days"`
	OutputDir         string `yaml:"out"`
	CACertificatePath string `yaml:"ca-certificate"`
	CAKeyPath         string `yaml:"ca-key"`
}

func (c *CreateCA) Run(args []string) int {
	var config CreateCAArguments

	flags := flag.NewFlagSet("create_ca", flag.ContinueOnError)
	flags.Usage = func() { c.Ui.Info(c.Help()) }
	flags.IntVar(&config.Days, "days", 0, "the validity period of the certificate in days")
	flags.StringVar(&config.OutputDir, "out", "./ca", "The output directory")
	flags.StringVar(&config.CACertificatePath, "ca-certificate", "", "the path to a CA certificate file")
	flags.StringVar(&config.CAKeyPath, "ca-key", "", "the path to a CA key file")

	if err := flags.Parse(args); err != nil {
		return 1
	}

	validationErrors := new(multierror.Error)
	if config.Days < 0 {
		multierror.Append(validationErrors, errors.New("days must be positive"))
	}

	caCertPathLen := len(config.CACertificatePath)
	caKeyPathLen := len(config.CAKeyPath)
	if (caCertPathLen > 0 && caKeyPathLen == 0) || (caKeyPathLen > 0 && caCertPathLen == 0) {
		multierror.Append(validationErrors, errors.New("both -ca-certificate and -ca-key options are required"))
	}

	if validationErrors.ErrorOrNil() != nil {
		c.Ui.Error(validationErrors.Error())
		return 1
	}

	/*default validity period*/
	years := 5
	days := 0

	if config.Days != 0 {
		days = config.Days
		years = 0
	}

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	var err error
	if caCertPathLen > 0 {
		caCert, err = readCertificateFromFile(config.CACertificatePath)
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}

		caKey, err = readRSAKeyFromFile(config.CAKeyPath)
		if err != nil {
			err := fmt.Errorf("error: %s. please note that only RSA keys are currently supported", err.Error())
			c.Ui.Error(err.Error())
			return 1
		}
	}

	outputDir := config.OutputDir
	err = generateCACertificate(years, days, outputDir, caCert, caKey)
	if err != nil {
		c.Ui.Error(err.Error())
	} else {
		if isBoringEnabled() {
			c.Ui.Output(fmt.Sprintf("A CA certificate & key file have been generated in the '%s' directory (FIPS mode enabled).", outputDir))
		} else {
			c.Ui.Output(fmt.Sprintf("A CA certificate & key file have been generated in the '%s' directory.", outputDir))
		}
	}
	return 0
}

func generateCACertificate(years int, days int, outputDir string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) error {
	serialNumber, err := generateSerialNumber(128)
	if err != nil {
		return fmt.Errorf("could not generate 128-bit serial number: %s", err.Error())
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySize)
	if err != nil {
		return fmt.Errorf("could not generate RSA private key: %s", err.Error())
	}

	cn := fmt.Sprintf("EventStoreDB CA %s", serialNumber.Text(16))
	subjectKeyID := generateKeyIDFromRSAPublicKey(privateKey.N, privateKey.E)
	authorityKeyID := subjectKeyID
	maxPathLen := 2

	if caCert != nil && caPrivateKey != nil {
		maxPathLen = -1
		cn = fmt.Sprintf("EventStoreDB Intermediate CA %s", serialNumber.Text(16))
		authorityKeyID = generateKeyIDFromRSAPublicKey(caPrivateKey.N, caPrivateKey.E)
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Event Store Ltd"},
			Country:      []string{"UK"},
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            maxPathLen,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(years, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        authorityKeyID,
	}

	parentCert := cert
	certPrivateKey := privateKey

	if caCert != nil && caPrivateKey != nil {
		parentCert = caCert
		certPrivateKey = caPrivateKey
	}

	privateKeyPem := new(bytes.Buffer)
	err = pem.Encode(privateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return fmt.Errorf("could not encode private key to PEM format: %s", err.Error())
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parentCert, &privateKey.PublicKey, certPrivateKey)
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

	certFile := "ca.crt"
	err = os.WriteFile(path.Join(outputDir, certFile), certPem.Bytes(), 0444)
	if err != nil {
		return fmt.Errorf("error writing CA certificate to %s: %s", certFile, err.Error())
	}

	keyFile := "ca.key"
	err = os.WriteFile(path.Join(outputDir, keyFile), privateKeyPem.Bytes(), 0400)
	if err != nil {
		return fmt.Errorf("error writing CA's private key to %s: %s", keyFile, err.Error())
	}

	return nil

}
func (c *CreateCA) Help() string {
	helpText := `
Usage: create_ca [options]
  Generate a root/intermediate CA TLS certificate to be used with EventStoreDB
Options:
  -days                       The validity period of the certificate in days (default: 5 years)
  -out                        The output directory (default: ./ca)
  -ca-certificate             The path to a CA certificate file for creating an intermediate CA certificate
  -ca-key                     The path to a CA key file for creating an intermediate CA certificate
`
	return strings.TrimSpace(helpText)
}

func (c *CreateCA) Synopsis() string {
	return "Generate a root/intermediate CA TLS certificate to be used with EventStoreDB"
}
