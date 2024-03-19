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
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateCA struct {
	Ui     cli.Ui
	Config CreateCAArguments
	Flags  *flag.FlagSet
}

type CreateCAArguments struct {
	Days              int    `yaml:"days"`
	OutputDir         string `yaml:"out"`
	CACertificatePath string `yaml:"ca-certificate"`
	CAKeyPath         string `yaml:"ca-key"`
	Name              string `yaml:"name"`
	Force             bool   `yaml:"force"`
}

func NewCreateCA(ui cli.Ui) *CreateCA {
	c := &CreateCA{Ui: ui}

	c.Flags = flag.NewFlagSet("create_ca", flag.ContinueOnError)
	c.Flags.IntVar(&c.Config.Days, "days", 0, DayFlagUsage)
	c.Flags.StringVar(&c.Config.OutputDir, "out", "./ca", OutDirFlagUsage)
	c.Flags.StringVar(&c.Config.CACertificatePath, "ca-certificate", "", CaCertFlagUsage)
	c.Flags.StringVar(&c.Config.CAKeyPath, "ca-key", "", CaKeyFlagUsage)
	c.Flags.StringVar(&c.Config.Name, "name", "ca", NameFlagUsage)
	c.Flags.BoolVar(&c.Config.Force, "force", false, ForceFlagUsage)
	return c
}

func (c *CreateCA) Run(args []string) int {
	if err := c.Flags.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	validationErrors := new(multierror.Error)
	if c.Config.Days < 0 {
		_ = multierror.Append(validationErrors, errors.New("days must be positive"))
	}

	caCertPathLen := len(c.Config.CACertificatePath)
	caKeyPathLen := len(c.Config.CAKeyPath)
	if (caCertPathLen > 0 && caKeyPathLen == 0) || (caKeyPathLen > 0 && caCertPathLen == 0) {
		_ = multierror.Append(validationErrors, errors.New("both -ca-certificate and -ca-key options are required"))
	}

	if validationErrors.ErrorOrNil() != nil {
		c.Ui.Error(validationErrors.Error())
		return 1
	}

	certErr := checkCertificatesLocationWithForce(c.Config.OutputDir, c.Config.Name, c.Config.Force)
	if certErr != nil {
		c.Ui.Error(certErr.Error())
		return 1
	}

	/*default validity period*/
	years := 5
	days := 0

	if c.Config.Days != 0 {
		days = c.Config.Days
		years = 0
	}

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	var err error
	if caCertPathLen > 0 {
		caCert, err = readCertificateFromFile(c.Config.CACertificatePath)
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}

		caKey, err = readRSAKeyFromFile(c.Config.CAKeyPath)
		if err != nil {
			err := fmt.Errorf("error: %s. please note that only RSA keys are currently supported", err.Error())
			c.Ui.Error(err.Error())
			return 1
		}
	}

	outputDir := c.Config.OutputDir
	err = generateCACertificate(years, days, outputDir, c.Config.Name, caCert, caKey, c.Config.Force)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	} else {
		if isBoringEnabled() {
			c.Ui.Output(fmt.Sprintf("A CA certificate & key file have been generated in the '%s' directory (FIPS mode enabled).", outputDir))
		} else {
			c.Ui.Output(fmt.Sprintf("A CA certificate & key file have been generated in the '%s' directory.", outputDir))
		}
	}

	return 0
}

func generateCACertificate(years int, days int, outputDir string, name string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, force bool) error {
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

	err = writeCertAndKey(outputDir, name, certPem, privateKeyPem, force)

	return err
}

func (c *CreateCA) Help() string {
	var helpText bytes.Buffer
	c.Flags.SetOutput(&helpText)
	c.Flags.PrintDefaults()
	return helpText.String()
}

func (c *CreateCA) Synopsis() string {
	return "Generate a root/intermediate CA TLS certificate to be used with EventStoreDB"
}
