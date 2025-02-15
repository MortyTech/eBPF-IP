package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func main() {
	// تعریف آرگومان‌های خط فرمان
	interfaceName := flag.String("interface", "", "Network interface to attach XDP program")
	flag.Parse()

	if *interfaceName == "" {
		log.Fatalf("Usage: %s --interface <interface>", os.Args[0])
	}

	// مسیر فایل eBPF کامپایل شده (program.o)
	ebpfProgramPath := "./program.o"

	// بررسی وجود فایل eBPF
	if _, err := os.Stat(ebpfProgramPath); os.IsNotExist(err) {
		log.Fatalf("eBPF program file not found: %s", ebpfProgramPath)
	}

	// دستور load برنامه eBPF با xdp-loader
	loadCmd := exec.Command("xdp-loader", "load", *interfaceName, ebpfProgramPath)
	loadCmd.Stdout = os.Stdout
	loadCmd.Stderr = os.Stderr

	fmt.Printf("Loading XDP program on interface %s...\n", *interfaceName)
	if err := loadCmd.Run(); err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	fmt.Println("XDP program loaded successfully.")

	// تابع برای unload کردن برنامه eBPF
	unloadXDP := func() {
		// دریافت ID برنامه eBPF با bpftool
		getProgIDCmd := exec.Command("bpftool", "prog", "list")
		grepCmd := exec.Command("grep", "xdp_prog")
		awkCmd := exec.Command("awk", "{print $1}")
		cutCmd := exec.Command("cut", "-d", ":", "-f", "1")

		// اتصال دستورات به یکدیگر با pipe
		grepCmd.Stdin, _ = getProgIDCmd.StdoutPipe()
		awkCmd.Stdin, _ = grepCmd.StdoutPipe()
		cutCmd.Stdin, _ = awkCmd.StdoutPipe()

		// اجرای دستورات
		getProgIDCmd.Start()
		grepCmd.Start()
		awkCmd.Start()
		output, err := cutCmd.Output()
		if err != nil {
			log.Printf("Failed to get XDP program ID: %v", err)
			return
		}

		// اگر برنامه‌ای پیدا نشد، خروج
		if len(output) == 0 {
			log.Println("No XDP program found to unload.")
			return
		}

		// تبدیل خروجی به برنامه ID
		progID := string(output)

		// دستور unload برنامه eBPF با xdp-loader
		unloadCmd := exec.Command("xdp-loader", "unload", *interfaceName, "-i", progID)
		unloadCmd.Stdout = os.Stdout
		unloadCmd.Stderr = os.Stderr

		fmt.Printf("Unloading XDP program with ID %s from interface %s...\n", progID, *interfaceName)
		if err := unloadCmd.Run(); err != nil {
			log.Printf("Failed to unload XDP program: %v", err)
			return
		}
		fmt.Println("XDP program unloaded successfully.")
	}

	// منتظر سیگنال‌های interrupt یا terminate بمانید
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	// Unload برنامه eBPF هنگام دریافت سیگنال
	fmt.Println("Detaching XDP program and exiting...")
	unloadXDP()
}
