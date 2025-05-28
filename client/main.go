package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/gedons/go_VPN/internal/config"
	"github.com/gedons/go_VPN/internal/crypto"
	"github.com/gedons/go_VPN/internal/tun"
)

func main() {
	// Load config
	conf, err := config.LoadClientConfig("configs/client-config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create TUN interface
	iface, err := tun.CreateTUNInterface(conf.TUNName)
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	// Setup UDP connection to server
	serverAddr := net.JoinHostPort(conf.ServerIp, fmt.Sprintf("%d", conf.ServerPort))
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to connect to VPN server: %v", err)
	}
	defer conn.Close()

	// Init encryption
	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		log.Fatalf("Failed to initialize cipher: %v", err)
	}

	log.Println("VPN client started and connected to server.")

	// Graceful shutdown on Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down VPN client...")
		os.Exit(0)
	}()

	// Read from TUN and send encrypted to server
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				log.Printf("Error reading from TUN: %v", err)
				continue
			}
			enc, err := cipher.Encrypt(buf[:n])
			if err != nil {
				log.Printf("Encrypt error: %v", err)
				continue
			}
			_, _ = conn.Write(enc)
		}
	}()

	// Read from server and write decrypted to TUN
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Error reading from server: %v", err)
			continue
		}
		dec, err := cipher.Decrypt(buf[:n])
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}
		_, _ = iface.Write(dec)
	}
}
