/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */

package common

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

type Config struct {
	// Documentation string about the command. Can be used in usage() commands.
	Doc string
	// Nmae of the command whose parameters will be captured by this config.
	CmdName string
	// name of the eBPF program name to load/unload, as written in the ELF Section.
	ProgName string
	// Interface name
	Dev string
	// The library to attach/detach the program. Can be netlink or ebpfgo.
	AttachLib string
	// Unload flag, will lead to detach the xdp program.
	DoUnload bool
	//Print the help
	Help bool
}

// NewConfigWithDoc creates a new Config struct with the the Doc field set.
func NewConfigWithDoc(doc string) Config {
	return Config{
		Doc: doc,
	}
}

// ParseCmdArgs obtains the command line arguments and save them to the Config struct.
func (c *Config) ParseCmdArgs() error {
	flag.StringVar(&c.Dev, "dev", "", "Operate on device <dev>")
	flag.StringVar(&c.ProgName, "progname", "", "Name of the XDP Program")
	flag.StringVar(&c.AttachLib, "attachlib", "ebpfgo", "Attach using the library [ebpfgo|netlink]")
	flag.BoolVar(&c.DoUnload, "unload", false, "unload the programs from the interface")
	flag.BoolVar(&c.Help, "help", false, "show help")
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprintf(w, "%s\n", c.Doc)
		fmt.Fprintf(w, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if c.Help {
		c.PrintUsage()
		os.Exit(0)
	}

	if c.Dev == "" {
		return errors.New("please specify an interface name")
	}

	return nil
}

// PrintUsage writes the documentation of the command line in the terminal
func (c *Config) PrintUsage() {
	flag.Usage()

}
