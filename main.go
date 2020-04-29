package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v4"

	"github.com/fatih/color"
	uuid "github.com/nu7hatch/gouuid"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var ifaceName string
var debug bool
var seconds int64
var vendorFile string

var history = []Network{}
var current = Network{}
var vendors = []VendorRecord{}

var conn *pgx.Conn

func init() {
	flag.BoolVar(&debug, "debug", false, "print debug log")
	flag.StringVar(&ifaceName, "iface", "eth0", "network interface name")
	flag.Int64Var(&seconds, "seconds", 10, "number of seconds to wait between each ARP broadcast")
	flag.StringVar(&vendorFile, "vendors", "vendors", "list of all vendors in nmap file format (MACPREFIX <TAB> VENDOR)")
	flag.Parse()

	var err error
	conn, err = pgx.Connect(context.Background(), os.Getenv("DB"))
	if err != nil {
		color.Red("could not connect to database: %v", err)
		os.Exit(1)
	}
}

func main() {
	var err error
	vendors, err = readVendors(vendorFile)
	if err != nil {
		color.Red("error while reading vendor file %s", vendorFile)
		os.Exit(1)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		color.Red("can not get interface %s, %s", ifaceName, err)
		os.Exit(1)
	}

	if err := scan(iface); err != nil {
		color.Yellow("interface %v: %v", ifaceName, err)
	}
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}
	if debug {
		color.Green("Using network range %v for interface %v", addr, iface.Name)

	}
	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)
	for {
		current = Network{
			Addresses: []Address{},
			Time:      time.Now(),
		}

		// Write our scan packets out to the handle.
		if err := writeARP(handle, iface, addr); err != nil {
			color.Yellow("error writing packets on %v: %v", iface.Name, err)
			return err
		}

		time.Sleep(time.Duration(seconds) * time.Second)

		current = deduplicateNetwork(current)
		history = append(history, current)

		last := history[len(history)-1]
		fmt.Println("Network at ", last.Time, "of", len(history))
		for _, addr := range last.Addresses {
			fmt.Printf("%s => %s (%s)\n", addr.IP, addr.MAC, addr.Vendor)
		}
		fmt.Println()

		for _, addr := range current.Addresses {
			uuid, err := uuid.NewV4()
			if err != nil {
				return err
			}

			_, err = conn.Exec(context.Background(), `
				INSERT INTO history VALUES ($1, $2, $3, $4, $5)
			`, uuid.String(), current.Time, addr.IP, addr.MAC, addr.Vendor)
			if err != nil {
				return err
			}
		}
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			// if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
			// 	// This is a packet I sent.
			// 	continue
			// }

			ip := net.IP(arp.SourceProtAddress).String()
			mac := net.HardwareAddr(arp.SourceHwAddress).String()

			splitted := strings.Split(mac, ":")
			macPrefix := strings.ToUpper(splitted[0] + splitted[1] + splitted[2])

			idx := len(vendors)
			macNumber, err := strconv.ParseUint(macPrefix, 16, 64)
			if err == nil {
				idx = sort.Search(len(vendors), func(i int) bool {
					number, _ := strconv.ParseUint(vendors[i].MACPrefix, 16, 64)
					return number >= macNumber
				})
			}

			vendor := ""
			if idx < len(vendors) {
				vendor = vendors[idx].Vendor
			}

			current.Addresses = append(current.Addresses, Address{
				IP:     ip,
				MAC:    mac,
				Vendor: vendor,
			})
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
