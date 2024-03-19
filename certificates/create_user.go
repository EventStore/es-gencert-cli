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

	multierror "github.com/hashicorp/go-multierror"
	"github.com/mitchellh/cli"
)

type CreateUser struct {
	Ui     cli.Ui
	Config CreateUserArguments
	Flags  *flag.FlagSet
}

type CreateUserArguments struct {
	Username          string `yaml:"username"`
	CACertificatePath string `yaml:"ca-certificate"`
	CAKeyPath         string `yaml:"ca-key"`
	Days              int    `yaml:"days"`
	OutputDir         string `yaml:"out"`
	Force             bool   `yaml:"force"`
}

func NewCreateUser(ui cli.Ui) *CreateUser {
	c := &CreateUser{Ui: ui}

	c.Flags = flag.NewFlagSet("create_user", flag.ContinueOnError)
	c.Flags.Usage = func() { c.Ui.Info(c.Help()) }
	c.Flags.StringVar(&c.Config.Username, "username", "", "the EventStoreDB user")
	c.Flags.StringVar(&c.Config.CACertificatePath, "ca-certificate", "./ca/ca.crt", CaCertFlagUsage)
	c.Flags.StringVar(&c.Config.CAKeyPath, "ca-key", "./ca/ca.key", CaKeyFlagUsage)
	c.Flags.IntVar(&c.Config.Days, "days", 0, DayFlagUsage)
	c.Flags.StringVar(&c.Config.OutputDir, "out", "", OutDirFlagUsage)
	c.Flags.BoolVar(&c.Config.Force, "force", false, ForceFlagUsage)

	return c
}

func (c *CreateUser) Run(args []string) int {
	if err := c.Flags.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	validationErrors := new(multierror.Error)

	if len(c.Config.Username) == 0 {
		_ = multierror.Append(validationErrors, errors.New("username is a required field"))
	}

	if len(c.Config.CACertificatePath) == 0 {
		_ = multierror.Append(validationErrors, errors.New("ca-certificate is a required field"))
	}

	if len(c.Config.CAKeyPath) == 0 {
		_ = multierror.Append(validationErrors, errors.New("ca-key is a required field"))
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

	outputDir := c.Config.OutputDir
	outputBaseFileName := "user-" + c.Config.Username

	if len(outputDir) == 0 {
		outputDir = outputBaseFileName
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

	err = generateUserCertificate(c.Config.Username, outputBaseFileName, caCert, caKey, years, days, outputDir, c.Config.Force)
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

func (c *CreateUser) Help() string {
	var helpText bytes.Buffer
	c.Flags.SetOutput(&helpText)
	c.Flags.PrintDefaults()
	return helpText.String()
}

func (c *CreateUser) Synopsis() string {
	return "Generate a user TLS certificate to be used with EventStoreDB clients"
}
