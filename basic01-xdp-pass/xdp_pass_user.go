/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/saidjawad/xdp-go-tutorial/common"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip xdp_pass_kern xdp_pass_kern.c

// DOC string that can be passed to the command line parser
const DOC = "Simple XDP prog doing XDP_Pass"

// The default file descriptor value used for detaching XDP programs from interfaces in Netlinks.
const NETLINK_DETACH_FD = -1

func main() {
	err := run()
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func run() error {
	config := common.NewConfigWithDoc(DOC)
	if err := config.ParseCmdArgs(); err != nil {
		config.PrintUsage()
		return fmt.Errorf("error parsing the command line args: %v", err)
	}

	if config.DoUnload {
		if err := detachXDPIface(config); err != nil {
			config.PrintUsage()
			return fmt.Errorf("error detaching programs from interface: %s, err: %v", config.Dev, err)
		}
		return nil
	}
	var collection xdp_pass_kernObjects
	err := loadXdp_pass_kernObjects(&collection, nil)
	if err != nil {
		return fmt.Errorf("error loading the program %v", err)
	}

	defer collection.Close()
	program := collection.xdp_pass_kernPrograms.XdpProgSimple
	if config.AttachLib == "netlink" {
		log.Printf("Attaching using netlink library")
		if err := attachXDPWithNetLink(config.Dev, program); err != nil {
			return fmt.Errorf("error attaching xdp with netlink %q", err)
		}
		return nil
	}

	log.Printf("Attach lib is not set, using the default ebpf-go method")
	if err := attachXDPWithEbpfLib(config.Dev, program); err != nil {
		return fmt.Errorf("error attaching xdp with ebpfgo %q", err)
	}
	return nil
}

// detaches an XDP program from an interface using Netlink library.
func detachXDPIface(config common.Config) error {
	iface, err := netlink.LinkByName(config.Dev)
	if err != nil {
		return err
	}
	fd := NETLINK_DETACH_FD
	if err := netlink.LinkSetXdpFd(iface, fd); err != nil {
		return err
	}
	log.Printf("Success: detached all programs from the interface %v\n", config.Dev)

	return nil
}

// attaches an XDP progrm to an interface using Netlink library.
func attachXDPWithNetLink(ifaceName string, prog *ebpf.Program) error {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	fd := prog.FD()
	if err := netlink.LinkSetXdpFd(iface, fd); err != nil {
		return err
	}
	progInfo, err := prog.Info()
	if err != nil {
		return err
	}
	progName := progInfo.Name
	progId, _ := progInfo.ID()
	log.Printf("Success: Loaded XDP program name:%v(with id:%v) on interface:%v(with iface index:%v)\n", progName, progId, ifaceName, iface.Attrs().Index)

	return nil
}

// attaches and XDP program to an interface using the ebpf-go library.
//
// This function shall be used with kernels 5.7+.
func attachXDPWithEbpfLib(ifaceName string, prog *ebpf.Program) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	l, err := ebpflink.AttachXDP(ebpflink.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	defer l.Close()
	progInfo, err := prog.Info()
	if err != nil {
		return err
	}
	progName := progInfo.Name
	progId, _ := progInfo.ID()
	log.Printf("Success: Loaded XDP program name:%v(with id:%v) on interface:%v(with iface index:%v)\n", progName, progId, ifaceName, iface.Index)

	keepAliveProg()
	return nil
}

// The helper function that keeps the user space program alive.
func keepAliveProg() {
	ticker := time.NewTicker(1 * time.Second)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-ticker.C:
		case <-sigs:
			return
		}
	}
}
