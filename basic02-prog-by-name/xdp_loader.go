package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/saidjawad/xdp-go-tutorial/common"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp_kern xdp_kern.c -- -I../headersß

// Struct allowing to only load the xdp_pass_func into the kernnel.
type XdpPassFunc struct {
	XdpPassFuncProg *ebpf.Program `ebpf:"xdp_pass_func"`
}

func (x *XdpPassFunc) Close() error {
	if err := x.XdpPassFuncProg.Close(); err != nil {
		return err
	}
	return nil
}

// Struct allowing to only load the xdp_drop_func into the kernnel.
type XdpDropFunc struct {
	XdpDropFuncProg *ebpf.Program `ebpf:"xdp_drop_func"`
}

func (x *XdpDropFunc) Close() error {
	if err := x.XdpDropFuncProg.Close(); err != nil {
		return err
	}
	return nil
}

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
	if config.ProgName == "" && !config.DoUnload {
		config.PrintUsage()
		return fmt.Errorf("please specify the program name")
	}

	if config.DoUnload {
		if err := detachXDPIface(config); err != nil {
			config.PrintUsage()
			return fmt.Errorf("error detaching programs from interface: %s, err: %v", config.Dev, err)
		}
		return nil
	}

	collectionSpecs, err := loadXdp_kern()
	if err != nil {
		log.Fatalf("Error loading the collections specs %v", err)
	}
	coll, program, err := loadProgramByName(collectionSpecs, config.ProgName)
	if err != nil {
		log.Fatalf("Error loading the program %v", err)
	}
	defer coll.Close()

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

// Loads all eBPF programs into the kernel, returns the pointer to the eBPF program specified by its name
func loadAllPrograms(progName string) (io.Closer, *ebpf.Program, error) {
	var obj xdp_kernObjects
	var closer io.Closer
	if err := loadXdp_kernObjects(&obj, nil); err != nil {
		return nil, nil, fmt.Errorf("error loading programs %v", err)
	}
	closer = &obj
	switch strings.ToLower(progName) {
	case "xdp_pass_func":
		return closer, obj.xdp_kernPrograms.XdpPassFunc, nil
	case "xdp_drop_func":
		return closer, obj.xdp_kernPrograms.XdpDropFunc, nil
	}
	obj.Close()
	return nil, nil, fmt.Errorf("could not find the program: %v", progName)
}

// Loads an eBPF program into the kernel from a CollectionSpecs object using its name.
//
// The programs and maps have to be defined in a struct.
func loadProgramCustomStruct(collectionSpecs *ebpf.CollectionSpec, progName string) (io.Closer, *ebpf.Program, error) {
	var closer io.Closer
	switch strings.ToLower(progName) {
	case "xdp_pass_func":
		var obj XdpPassFunc
		if err := collectionSpecs.LoadAndAssign(&obj, nil); err != nil {
			return nil, nil, fmt.Errorf("error loading program :%v, %v", progName, err)
		}
		closer = &obj
		return closer, obj.XdpPassFuncProg, nil
	case "xdp_drop_func":
		var obj XdpDropFunc
		if err := collectionSpecs.LoadAndAssign(&obj, nil); err != nil {
			return nil, nil, fmt.Errorf("error loading program :%v, %v", progName, err)
		}
		closer = &obj
		return closer, obj.XdpDropFuncProg, nil
	default:
		return nil, nil, fmt.Errorf("could not find the program :%v", progName)
	}
}

// Loads an eBPF program into the kernel from a CollectionSpecs object using its name.
//
// It modifies the ColectionSpecs object by discarding other programs.
func loadProgramByName(collectionSpecs *ebpf.CollectionSpec, progName string) (*ebpf.Collection, *ebpf.Program, error) {
	programSpec, ok := collectionSpecs.Programs[progName]
	if !ok {
		return nil, nil, fmt.Errorf("could not find program with name %v", progName)
	}
	//Only keep the program spec with the specified name
	collectionSpecs.Programs = map[string]*ebpf.ProgramSpec{progName: programSpec}
	collection, err := ebpf.NewCollection(collectionSpecs)
	if err != nil {
		return collection, nil, err
	}
	program := collection.Programs[progName]
	return collection, program, err

}

// detaches an XDP program from an interface using Netlink library.
func detachXDPIface(config common.Config) error {
	log.Printf("Detaching all programs from the interface")
	iface, err := netlink.LinkByName(config.Dev)
	if err != nil {
		return err
	}
	fd := NETLINK_DETACH_FD
	if err := netlink.LinkSetXdpFd(iface, fd); err != nil {
		return err
	}
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
