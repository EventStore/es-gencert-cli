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
	"os"
	"path"
	"strings"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateCA struct {
	Ui cli.Ui
}

type CreateCAArguments struct {
	Days      int
	OutputDir string
}

func (c *CreateCA) Run(args []string) int {
	var config CreateCAArguments

	flags := flag.NewFlagSet("create_ca", flag.ContinueOnError)
	flags.Usage = func() { c.Ui.Info(c.Help()) }
	flags.IntVar(&config.Days, "days", 0, "the validity period of the certificate in days")
	flags.StringVar(&config.OutputDir, "out", "./ca", "The output directory")

	if err := flags.Parse(args); err != nil {
		return 1
	}

	validationErrors := new(multierror.Error)
	if config.Days < 0 {
		multierror.Append(validationErrors, errors.New("days must be positive"))
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

	outputDir := config.OutputDir
	err := generateCACertificate(defaultKeySize, years, days, outputDir)
	if err != nil {
		c.Ui.Error(err.Error())
	} else {
		c.Ui.Output(fmt.Sprintf("A CA certificate & key file have been generated in the '%s' directory", outputDir))
	}
	return 0
}

func generateCACertificate(keysize int, years int, days int, outputDir string) error {
	serialNumber, err := generateSerialNumber(128)
	if err != nil {
		return fmt.Errorf("could not generate 128-bit serial number: %s", err.Error())
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySize)
	if err != nil {
		return fmt.Errorf("could not generate RSA private key: %s", err.Error())
	}

	keyID := generateKeyIDFromRSAPublicKey(privateKey.N, privateKey.E)

	cn := fmt.Sprintf("EventStoreDB CA %s", serialNumber.Text(16))

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Event Store Ltd"},
			Country:      []string{"UK"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(years, 0, days),
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          keyID,
		AuthorityKeyId:        keyID,
	}

	privateKeyPem := new(bytes.Buffer)
	pem.Encode(privateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return fmt.Errorf("could not encode private key to PEM format: %s", err.Error())
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
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
	err = ioutil.WriteFile(path.Join(outputDir, certFile), certPem.Bytes(), 0444)
	if err != nil {
		return fmt.Errorf("error writing CA certificate to %s: %s", certFile, err.Error())
	}

	keyFile := "ca.key"
	err = ioutil.WriteFile(path.Join(outputDir, keyFile), privateKeyPem.Bytes(), 0400)
	if err != nil {
		return fmt.Errorf("error writing CA's private key to %s: %s", keyFile, err.Error())
	}

	return nil

}
func (c *CreateCA) Help() string {
	helpText := `
Usage: create_ca [options]
  Generate a root/CA TLS certificate to be used with EventStoreDB
Options:
  -days                       The validity period of the certificate in days (default: 5 years)
  -out                        The output directory (default: ./ca)
`
	return strings.TrimSpace(helpText)
}

func (c *CreateCA) Synopsis() string {
	return "Generate a root/CA TLS certificate to be used with EventStoreDB"
}
