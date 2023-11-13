package certificates

import (
	"log"
	"os"
	"strings"

	"github.com/mitchellh/cli"
)

type Certificates struct {
	UI cli.Ui
}

func (command *Certificates) Run(args []string) int {
	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}
	c := cli.NewCLI("Event Store CLI certificates", "")
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"create-ca": func() (cli.Command, error) {
			return &CreateCA{
				UI: &cli.ColoredUi{
					Ui:          ui,
					OutputColor: cli.UiColorBlue,
				},
			}, nil
		},
		"create-node": func() (cli.Command, error) {
			return &CreateNode{
				UI: &cli.ColoredUi{
					Ui:          ui,
					OutputColor: cli.UiColorBlue,
				},
			}, nil
		},
	}
	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}

func (command *Certificates) Help() string {
	helpText := `
usage: certificates [--help] <command> [<args>]

Available commands:
`
	helpText += command.Synopsis()
	return strings.TrimSpace(helpText)
}

func (command *Certificates) Synopsis() string {
	return "certificates (create_ca, create_node)"
}
