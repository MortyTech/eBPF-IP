package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/olekukonko/tablewriter"
)

// ساختار flow_key مطابق با تعریف شما
type flowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	_        [3]byte // Padding برای مطابقت با اندازه ساختار در eBPF
}

// ساختار برای نگهداری ردیف‌های جدول
type tableRow struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	Byte     int
}

func main() {
	// نام map
	mapName := "flow_stats"

	// پیدا کردن ID مربوط به map با استفاده از bpftool
	mapID, err := findMapID(mapName)
	if err != nil {
		log.Fatalf("Failed to find map ID: %v", err)
	}

	// مسیر موقت برای pin کردن map
	tempPinPath := fmt.Sprintf("/sys/fs/bpf/temp_%s", mapName)

	// اطمینان از پاک شدن فایل موقت حتی در صورت وقوع خطا یا دریافت سیگنال
	cleanup := func() {
		if err := os.Remove(tempPinPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Failed to remove temp pin path: %v", err)
		}
		fmt.Println("Temporary pin path removed:", tempPinPath)
	}
	defer cleanup()

	// مدیریت سیگنال‌ها برای خروج تمیز از برنامه
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nExiting program...")
		cleanup() // پاک کردن فایل موقت قبل از خروج
		os.Exit(0)
	}()

	// Pin کردن map به مسیر موقت با استفاده از bpftool
	if err := pinMap(mapID, tempPinPath); err != nil {
		log.Fatalf("Failed to pin map: %v", err)
	}
	fmt.Println("Map pinned to temporary path:", tempPinPath)

	// باز کردن map از مسیر موقت
	m, err := ebpf.LoadPinnedMap(tempPinPath, nil)
	if err != nil {
		log.Fatalf("Failed to load pinned map: %v", err)
	}
	defer m.Close()

	// ایجاد جدول برای نمایش داده‌ها
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "byte"})
	table.SetBorder(false) // غیرفعال کردن خطوط مرزی جدول

	// حلقه بی‌نهایت برای خواندن و نمایش داده‌های map هر ثانیه
	for {
		// پاک کردن ردیف‌های قبلی از جدول
		table.ClearRows()

		// خواندن تمام کلیدها و مقادیر از map
		var key flowKey
		var value uint64
		iter := m.Iterate()
		var rows []tableRow
		for iter.Next(&key, &value) {
			// افزودن ردیف جدید به لیست
			rows = append(rows, tableRow{
				SrcIP:    intToIP(key.SrcIP),
				DstIP:    intToIP(key.DstIP),
				SrcPort:  fmt.Sprintf("%d", key.SrcPort),
				DstPort:  fmt.Sprintf("%d", key.DstPort),
				Protocol: protocolToName(key.Protocol), // تبدیل عدد پروتکل به نام
				Byte:     int(value),
			})
		}
		if iter.Err() != nil {
			log.Printf("Failed to iterate map: %v", iter.Err())
		}

		// مرتب‌سازی ردیف‌ها بر اساس ستون BYTE (از بیشترین به کمترین)
		sort.Slice(rows, func(i, j int) bool {
			return rows[i].Byte > rows[j].Byte
		})

		// افزودن ردیف‌های مرتب‌شده به جدول
		for _, row := range rows {
			table.Append([]string{
				row.SrcIP,
				row.DstIP,
				row.SrcPort,
				row.DstPort,
				row.Protocol,
				strconv.Itoa(row.Byte),
			})
		}

		// پاک کردن صفحه و نمایش جدول
		fmt.Print("\033[H\033[2J") // پاک کردن صفحه ترمینال
		table.Render()             // نمایش جدول

		// خوابیدن برای یک ثانیه
		time.Sleep(1 * time.Second)
	}
}

// تابع کمکی برای تبدیل uint32 به IP
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	)
}

// تابع برای تبدیل عدد پروتکل به نام
func protocolToName(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 112:
		return "VRRP"
	default:
		return fmt.Sprintf("Unknown (%d)", protocol) // اگر پروتکل ناشناخته بود، عدد آن برگردانده می‌شود
	}
}

// تابع برای پیدا کردن ID map با استفاده از bpftool
func findMapID(mapName string) (string, error) {
	// اجرای دستور bpftool برای پیدا کردن ID map
	cmd := exec.Command("bpftool", "map", "show", "name", mapName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run bpftool: %v", err)
	}

	// جستجو برای ID map
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			// استخراج ID از خط مربوطه
			fields := strings.Fields(line)
			if len(fields) > 0 {
				return strings.TrimSuffix(fields[0], ":"), nil
			}
		}
	}

	return "", fmt.Errorf("map not found: %s", mapName)
}

// تابع برای pin کردن map با استفاده از bpftool
func pinMap(mapID, pinPath string) error {
	cmd := exec.Command("bpftool", "map", "pin", "id", mapID, pinPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to pin map: %v", err)
	}
	return nil
}
