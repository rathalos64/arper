package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"strings"
)

func readVendors(file string) ([]VendorRecord, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	vendors := []VendorRecord{}

	reader := bufio.NewReader(fh)
	for line, _, err := reader.ReadLine(); err == nil; line, _, err = reader.ReadLine() {
		splitted := strings.SplitN(string(line[:]), " ", 2)
		vendors = append(vendors, VendorRecord{
			MACPrefix: strings.TrimSpace(splitted[0]),
			Vendor:    strings.TrimSpace(splitted[1]),
		})
	}

	return vendors, nil
}

func deduplicateNetwork(network Network) Network {
	lookup := map[string]Address{}
	for _, addr := range network.Addresses {
		if _, ok := lookup[addr.IP]; !ok {
			lookup[addr.IP] = addr
		}
	}

	addresses := []Address{}
	for _, addr := range lookup {
		addresses = append(addresses, addr)
	}

	network.Addresses = addresses
	return network
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}
