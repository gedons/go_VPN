package main

import (
	"log"
	"net"

	"github.com/gedons/go_VPN/internal/config"
	"github.com/gedons/go_VPN/internal/crypto"
)

func main() {
	conf, err := config.LoadClientConfig("configs/server-config.yaml")
	if err != nil {
		log.Fatalf("Failed to load server config: %v", err)
	}

	addr := net.UDPAddr{
		IP:   net.ParseIP(conf.ServerIp),
		Port: conf.ServerPort,
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer conn.Close()

	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		log.Fatalf("Cipher init error: %v", err)
	}

	log.Printf("Server listening on %s:%d", conf.ServerIp, conf.ServerPort)

	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		decrypted, err := cipher.Decrypt(buf[:n])
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}

		msg := string(decrypted)
		log.Printf("Received from %s: %s", clientAddr.String(), msg)

		// Echo it back
		response, _ := cipher.Encrypt([]byte("Acknowledged: " + msg))
		_, _ = conn.WriteToUDP(response, clientAddr)
	}
}
