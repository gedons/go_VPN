package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/gedons/go_VPN/internal/config"
	"github.com/gedons/go_VPN/internal/crypto"
)

func main() {
	conf, err := config.LoadClientConfig("configs/client-config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	serverAddr := net.JoinHostPort(conf.ServerIp, fmt.Sprintf("%d", conf.ServerPort))
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Fatalf("UDP dial error: %v", err)
	}
	defer conn.Close()

	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		log.Fatalf("Cipher init error: %v", err)
	}

	fmt.Println("Connected to VPN server. Type messages to send securely.")
	reader := bufio.NewReader(os.Stdin)

	// Send input from user
	for {
		fmt.Print("> ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)

		if text == "exit" {
			break
		}

		encrypted, err := cipher.Encrypt([]byte(text))
		if err != nil {
			log.Printf("Encrypt error: %v", err)
			continue
		}

		_, _ = conn.Write(encrypted)

		// Read response
		resp := make([]byte, 1500)
		n, err := conn.Read(resp)
		if err == nil {
			decrypted, _ := cipher.Decrypt(resp[:n])
			fmt.Println("Server:", string(decrypted))
		}
	}
}
