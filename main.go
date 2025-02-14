package main

import (
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled eBPF program
	collection, err := ebpf.LoadCollection("xdp_count_bytes.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF collection: %v", err)
	}
	defer collection.Close()

	// Get the XDP program
	xdpProg := collection.Programs["xdp_count_bytes"]
	if xdpProg == nil {
		log.Fatalf("Failed to find xdp_count_bytes program")
	}

	// Attach the XDP program to the network interface
	interfaceName := "ens3" // Replace with your network interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", interfaceName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	log.Printf("XDP program attached to %s", interfaceName)

	// Get the map for byte counts
	byteCountMap := collection.Maps["ip_byte_count"]
	if byteCountMap == nil {
		log.Fatalf("Failed to find ip_byte_count map")
	}

	// Target IP address (185.79.97.55 in network byte order)
	targetIP := net.ParseIP("185.79.97.55").To4()
	if targetIP == nil {
		log.Fatalf("Failed to parse target IP")
	}
	ipKey := uint32(targetIP[0]) | uint32(targetIP[1])<<8 | uint32(targetIP[2])<<16 | uint32(targetIP[3])<<24

	// Read the byte count every second
	for {
		var byteCount uint64
		if err := byteCountMap.Lookup(ipKey, &byteCount); err != nil {
			log.Printf("Failed to lookup byte count: %v", err)
		} else {
			log.Printf("Bytes consumed by 185.79.97.55: %d bytes", byteCount)
		}

		// Reset the byte count for the next second
		if err := byteCountMap.Put(ipKey, uint64(0)); err != nil {
			log.Printf("Failed to reset byte count: %v", err)
		}

		time.Sleep(1 * time.Second)
	}
}
