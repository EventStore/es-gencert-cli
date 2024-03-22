package certificates

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/mitchellh/cli"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"strings"
	"sync"
)

type CreateCertificates struct {
	Ui     cli.Ui
	Config CreateCertificateArguments
	Flags  *flag.FlagSet
}

type CreateCertificateArguments struct {
	ConfigPath string
	Force      bool `yaml:"force"`
}

type Config struct {
	Certificates struct {
		CaCerts []CreateCAArguments   `yaml:"ca-certs"`
		Nodes   []CreateNodeArguments `yaml:"node-certs"`
		Users   []CreateUserArguments `yaml:"user-certs"`
	} `yaml:"certificates"`
}

func NewCreateCerts(ui cli.Ui) *CreateCertificates {
	c := &CreateCertificates{Ui: ui}

	c.Flags = flag.NewFlagSet("create_certs", flag.ContinueOnError)
	c.Flags.StringVar(&c.Config.ConfigPath, "config-file", "./certs.yml", "The config yml file")
	c.Flags.BoolVar(&c.Config.Force, "force", false, ForceFlagUsage)
	return c
}

func (c *CreateCertificates) Run(args []string) int {
	if err := c.Flags.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	configData, err := os.ReadFile(c.Config.ConfigPath)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}
	config := Config{}

	if yaml.Unmarshal(configData, &config) != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	certErr := c.checkPaths(config, c.Config.Force)
	if certErr != nil {
		c.Ui.Error(certErr.Error())
		return 1
	}

	if c.generateCaCerts(config, c.Config.Force) != 0 || c.generateNodes(config, c.Config.Force) != 0 || c.generateUsers(config, c.Config.Force) != 0 {
		return 1
	}

	return 0
}

func (c *CreateCertificates) checkPaths(config Config, force bool) error {
	var once sync.Once
	var certError error
	var wg sync.WaitGroup

	checkCertFiles := func(certificateName, dir string) {
		defer wg.Done()
		if err := checkCertificatesLocationWithForce(dir, certificateName, force); err != nil {
			once.Do(func() {
				certError = err
			})
		}
	}

	// Check CA certificate and key paths
	for _, caCert := range config.Certificates.CaCerts {
		wg.Add(1)
		go checkCertFiles(caCert.Name, caCert.OutputDir)
	}

	// Check Node certificate and key paths
	for _, node := range config.Certificates.Nodes {
		wg.Add(1)
		go checkCertFiles(node.Name, node.OutputDir)
	}

	wg.Wait()
	return certError
}

func (c *CreateCertificates) generateUsers(config Config, force bool) int {
	for _, user := range config.Certificates.Users {
		user.Force = force
		createUser := NewCreateUser(&cli.ColoredUi{
			Ui:          c.Ui,
			OutputColor: cli.UiColorBlue,
		})
		if createUser.Run(toArguments(user)) != 0 {
			return 1
		}
	}
	return 0
}

func (c *CreateCertificates) generateNodes(config Config, force bool) int {
	for _, node := range config.Certificates.Nodes {
		node.Force = force
		createNode := NewCreateNode(&cli.ColoredUi{
			Ui:          c.Ui,
			OutputColor: cli.UiColorBlue,
		})
		if createNode.Run(toArguments(node)) != 0 {
			return 1
		}
	}
	return 0
}

func (c *CreateCertificates) generateCaCerts(config Config, force bool) int {
	for _, caCert := range config.Certificates.CaCerts {
		caCert.Force = force
		caCreator := NewCreateCA(&cli.ColoredUi{
			Ui:          c.Ui,
			OutputColor: cli.UiColorBlue,
		})
		if caCreator.Run(toArguments(caCert)) != 0 {
			return 1
		}
	}
	return 0
}

func toArguments(config interface{}) []string {
	var args strings.Builder
	fields := reflect.ValueOf(config)
	for i := 0; i < fields.NumField(); i++ {
		key := reflect.TypeOf(config).Field(i).Tag.Get("yaml")
		val := fields.Field(i).Interface()
		if fields.Field(i).Kind() == reflect.Bool {
			if val.(bool) {
				args.WriteString(fmt.Sprintf("-%s ", key))
			}
		} else {
			value := fmt.Sprintf("%v", val)
			if len(value) > 0 {
				args.WriteString(fmt.Sprintf("-%s %s ", key, value))
			}
		}
	}
	return strings.Fields(args.String())
}

func (c *CreateCertificates) Help() string {
	var helpText bytes.Buffer
	c.Flags.SetOutput(&helpText)
	c.Flags.PrintDefaults()
	return helpText.String()
}

func (c *CreateCertificates) Synopsis() string {
	return "Generate Certificates for both the CA and the eventstore Nodes in a single command using a config yml"
}
