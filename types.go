package main

import "time"

type Network struct {
	Time      time.Time
	Addresses []Address
}

type Address struct {
	IP     string
	MAC    string
	Vendor string
}

type VendorRecord struct {
	MACPrefix string
	Vendor    string
}
