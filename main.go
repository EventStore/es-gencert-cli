package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/eventstore/es-gencert-cli/certificates"
	"github.com/mitchellh/cli"
)

var version = "0.0.0"

func main() {
	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	appName := "Event Store Certificate Generation CLI"
	args := os.Args[1:]
	c := cli.NewCLI(appName, version)
	c.Args = args

	flags := flag.NewFlagSet("config", flag.ContinueOnError)

	if !c.IsVersion() && !c.IsHelp() {
		flags.Parse(os.Args[1:])
		args = flags.Args()
	}

	c = cli.NewCLI(appName, version)
	c.Args = args

	c.Commands = map[string]cli.CommandFactory{
		"create-ca": func() (cli.Command, error) {
			return &certificates.CreateCA{
				Ui: &cli.ColoredUi{
					Ui:          ui,
					OutputColor: cli.UiColorBlue,
				},
			}, nil
		},
		"create-node": func() (cli.Command, error) {
			return &certificates.CreateNode{
				Ui: &cli.ColoredUi{
					Ui:          ui,
					OutputColor: cli.UiColorBlue,
				},
			}, nil
		},
	}
	c.HelpFunc = createGeneralHelpFunc(appName, flags)

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}

	os.Exit(exitStatus)
}

func createGeneralHelpFunc(appName string, flags *flag.FlagSet) cli.HelpFunc {
	return func(cf map[string]cli.CommandFactory) string {
		buf := new(bytes.Buffer)
		w := new(tabwriter.Writer)
		w.Init(buf, 0, 8, 4, '\t', 0)

		fmt.Fprintf(w, "usage: %s [<options>] <command> [<args>]\n\n", appName)
		fmt.Fprintln(w, "Available options are:")
		fmt.Fprintln(w, "--version\tGet the version of Event Store CLI")
		fmt.Fprintln(w, "--help\tDisplay help")

		flags.VisitAll(func(fl *flag.Flag) {
			fmt.Fprintf(w, "--%s\t%s\n", fl.Name, fl.Usage)
		})
		fmt.Fprintln(w)

		fmt.Fprintln(w, "Available commands are:")
		for key, cmdF := range cf {
			cmd, _ := cmdF()
			fmt.Fprintf(w, "%s\t%s\n", key, cmd.Synopsis())
		}

		w.Flush()
		return buf.String()
	}
}
