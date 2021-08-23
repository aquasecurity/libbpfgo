package main

/*
#include <arpa/inet.h>
#include <netinet/in.h>
*/

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"net"
	"os"
	"time"
)

func okexit() {
	fmt.Fprintf(os.Stdout, "success\n")
	os.Exit(0)
}

func errexit(why error) {
	fmt.Fprintf(os.Stdout, "error: %s\n", why)
	os.Exit(1)
}

func errtimeout() {
	fmt.Fprintf(os.Stdout, "timeout\n")
	os.Exit(3)
}

// I have not packed the data struct shared among bpf and userland
// discover holes and paddings with: pahole -C struct_name ./binary
type data struct {
	Comm      [16]byte // 00 - 16 : command (task_comm_len)
	Pid       uint32   // 16 - 20 : process id
	Uid       uint32   // 20 - 24 : user id
	Gid       uint32   // 24 - 28 : group id
	LoginUid  uint32   // 28 - 32 : real user (login/terminal)
	Family    uint8    // 32 - 33 : network family
	Proto     uint8    // 33 - 34 : protocol (sock.h: u8 older, u16 newer)
	SPort     uint16   // 34 - 36 : source port
	DPort     uint16   // 36 - 38 : dest port
	_         [2]byte  // 38 - 40 : -- (hole for cache align)
	SAddr     uint32   // 40 - 44 : source address
	SAddr6    [16]byte // 44 - 60 : source address (IPv6)
	DAddr     uint32   // 60 - 64 : dest address
	DAddr6    [16]byte // 64 - 80 : dest address (IPv6)
	TheSource uint8    // 80 - 81 : am I originating the packet ?
	_         [3]byte  // 81 - 84 : -- (padding, total = 84 bytes)
}

type gdata struct {
	Comm     string
	Pid      uint
	Uid      uint
	Gid      uint
	LoginUid uint
	Family   uint
	Proto    uint
	SPort    uint
	DPort    uint
	SAddr    string
	DAddr    string
}

func main() {

	var err error

	var bpfModule *bpf.Module
	var bpfMapEvents *bpf.BPFMap
	var bpfProgTcpConnect *bpf.BPFProg
	var perfBuffer *bpf.PerfBuffer

	var eventsChannel chan []byte
	var lostChannel chan uint64

	// create BPF module using BPF object file
	bpfModule, err = bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		errexit(err)
	}
	defer bpfModule.Close()

	// BPF map "events": resize it before object is loaded
	bpfMapEvents, err = bpfModule.GetMap("events")
	err = bpfMapEvents.Resize(8192)
	if err != nil {
		errexit(err)
	}

	// load BPF object from BPF module
	if err = bpfModule.BPFLoadObject(); err != nil {
		errexit(err)
	}

	// get BPF program from BPF object
	bpfProgTcpConnect, err = bpfModule.GetProgram("tcp_connect")
	if err != nil {
		errexit(err)
	}

	// attach to BPF program to kprobe
	_, err = bpfProgTcpConnect.AttachKprobe("tcp_connect")
	if err != nil {
		errexit(err)
	}

	// channel for events (and lost events)
	eventsChannel = make(chan []byte)
	lostChannel = make(chan uint64)

	perfBuffer, err = bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		errexit(err)
	}

	// start perf event polling (will receive events through eventChannel)
	perfBuffer.Start()

	fmt.Println("Listening for tcp_connect(), <Ctrl-C> or or SIG_TERM to end it.")

	timeout := make(chan bool)
	allgood := make(chan bool)

	go func() {
		time.Sleep(60 * time.Second) // this timeout is bigger than Makefile one
		timeout <- true
	}()

	go func() {
		// receive events until channel is closed
		for dataRaw := range eventsChannel {

			var dt data
			var dataBuffer *bytes.Buffer

			dataBuffer = bytes.NewBuffer(dataRaw)

			err = binary.Read(dataBuffer, binary.LittleEndian, &dt)
			if err != nil {
				fmt.Println(err)
				continue
			}

			var bsport = make([]byte, 2)
			var bdport = make([]byte, 2)
			binary.BigEndian.PutUint16(bsport, dt.SPort)
			binary.BigEndian.PutUint16(bdport, dt.DPort)

			godata := gdata{
				Comm:     string(bytes.TrimRight(dt.Comm[:], "\x00")),
				Pid:      uint(dt.Pid),
				Uid:      uint(dt.Uid),
				Gid:      uint(dt.Gid),
				LoginUid: uint(dt.LoginUid),
				Family:   uint(dt.Family),
				Proto:    uint(dt.Proto),
				SPort:    uint(binary.LittleEndian.Uint16(bsport)),
				DPort:    uint(binary.LittleEndian.Uint16(bdport)),
			}

			// TCPv4 only example

			if godata.Family == 2 {

				var LeSAddr = make([]byte, 4)
				var LeDAddr = make([]byte, 4)

				binary.LittleEndian.PutUint32(LeSAddr, dt.SAddr)
				binary.LittleEndian.PutUint32(LeDAddr, dt.DAddr)
				godata.SAddr = net.IP.String(LeSAddr)
				godata.DAddr = net.IP.String(LeDAddr)

				fmt.Fprintf(os.Stdout, "%s (pid: %d) (loginuid: %d) | (proto: %d) %s (%d) => %s (%d)\n",
					godata.Comm, godata.Pid,
					godata.LoginUid, godata.Proto,
					godata.SAddr, godata.SPort,
					godata.DAddr, godata.DPort)

				if godata.DAddr == "127.0.0.1" {
					if godata.DPort == 12345 {
						// magic connection makes test succeed
						allgood <- true
					}
				}
			}
		}
	}()

	select {
	case <-allgood:
		okexit()
	case <-timeout:
		errtimeout()
	}
}
