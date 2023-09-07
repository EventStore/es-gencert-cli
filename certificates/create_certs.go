package certificates

import (
	"flag"
	"fmt"
	"github.com/mitchellh/cli"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"strings"
)

type CreateCertificates struct {
	Ui cli.Ui
}

type CreateCertificateArguments struct {
	ConfigPath string
}

type Config struct {
	Certificates struct {
		CaCerts []CreateCAArguments   `yaml:"ca-certs"`
		Nodes   []CreateNodeArguments `yaml:"node-certs"`
	} `yaml:"certificates"`
}

func (c *CreateCertificates) Run(args []string) int {
	var arguments CreateCertificateArguments
	flags := flag.NewFlagSet("create_certs", flag.ContinueOnError)
	flags.Usage = func() { c.Ui.Info(c.Help()) }
	flags.StringVar(&arguments.ConfigPath, "config-file", "./certs.yml", "The config yml file")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	configData, err := os.ReadFile(arguments.ConfigPath)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}
	config := Config{}

	if yaml.Unmarshal(configData, &config) != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if c.generateCaCerts(config) != 0 || c.generateNodes(config) != 0 {
		return 1
	}

	return 0

}

func (c *CreateCertificates) generateNodes(config Config) int {
	for _, node := range config.Certificates.Nodes {
		createNode := CreateNode{
			Ui: &cli.ColoredUi{
				Ui:          c.Ui,
				OutputColor: cli.UiColorBlue,
			},
		}
		if createNode.Run(toArguments(node)) != 0 {
			return 1
		}
	}
	return 0
}

func (c *CreateCertificates) generateCaCerts(config Config) int {
	for _, ca := range config.Certificates.CaCerts {
		createCa := CreateCA{
			Ui: &cli.ColoredUi{
				Ui:          c.Ui,
				OutputColor: cli.UiColorBlue,
			},
		}
		if createCa.Run(toArguments(ca)) != 0 {
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
		value := fmt.Sprintf("%v", fields.Field(i).Interface())
		if len(value) > 0 {
			args.WriteString(fmt.Sprintf("-%s %s ", key, value))
		}
	}
	return strings.Fields(args.String())
}

func (c *CreateCertificates) Help() string {
	helpText := `
Usage: create_certs [options]
  Generate ca and node Certificates from an yml configuration file.
Options:
  -config-file    the path to the yml config file
`
	return strings.TrimSpace(helpText)
}

func (c *CreateCertificates) Synopsis() string {
	return "Generate Certificates for both the CA and the eventstore Nodes in a single command using a config yml"
}
