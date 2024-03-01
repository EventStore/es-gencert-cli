package certificates

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/mitchellh/cli"
	"gopkg.in/yaml.v3"
)

type CreateCertificates struct {
	Ui cli.Ui
}

type CreateCertificateArguments struct {
	ConfigPath string
	Force      bool `yaml:"force"`
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
	flags.BoolVar(&arguments.Force, "force", false, forceOption)

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

	if err := c.checkPaths(config, arguments.Force); err {
		c.Ui.Error(ErrFileExists)
		return 1
	}

	if c.generateCaCerts(config, arguments.Force) != 0 || c.generateNodes(config, arguments.Force) != 0 {
		return 1
	}

	return 0
}

func (c *CreateCertificates) checkPaths(config Config, force bool) bool {
	// If any certs file exists and the force flag isn't provided, it returns an
	// error. Otherwise, it returns false, indicating that certificate generation
	// can proceed safely.

	var errorMutex sync.Mutex
	var error bool
	var wg sync.WaitGroup

	checkFile := func(filePath string) {
		defer wg.Done()
		if fileExists(filePath, force) {
			errorMutex.Lock()
			error = true
			errorMutex.Unlock()
		}
	}

	// Check CA certificate and key paths
	for _, caCert := range config.Certificates.CaCerts {
		wg.Add(2)
		go checkFile(caCert.CACertificatePath)
		go checkFile(caCert.CAKeyPath)
	}

	// Check Node certificate and key paths
	for _, node := range config.Certificates.Nodes {
		wg.Add(4)
		go checkFile(node.CACertificatePath)
		go checkFile(node.CAKeyPath)
		go checkFile(path.Join(node.OutputDir, "node.crt"))
		go checkFile(path.Join(node.OutputDir, "node.key"))
	}

	wg.Wait()
	return error
}

func (c *CreateCertificates) generateNodes(config Config, force bool) int {
	for _, node := range config.Certificates.Nodes {
		node.Force = force
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

func (c *CreateCertificates) generateCaCerts(config Config, force bool) int {
	coloredUI := &cli.ColoredUi{
		Ui:          c.Ui,
		OutputColor: cli.UiColorBlue,
	}

	for _, caCert := range config.Certificates.CaCerts {
		caCert.Force = force
		caCreator := CreateCA{Ui: coloredUI}
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
	var buffer bytes.Buffer

	w := tabwriter.NewWriter(&buffer, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "Usage: create_certs [options]")
	fmt.Fprintln(w, c.Synopsis())
	fmt.Fprintln(w, "Options:")

	writeHelpOption(w, "config-file", "The path to the yml config file.")
	writeHelpOption(w, "force", forceOption)

	w.Flush()

	return strings.TrimSpace(buffer.String())
}

func (c *CreateCertificates) Synopsis() string {
	return "Generate Certificates for both the CA and the eventstore Nodes in a single command using a config yml"
}
