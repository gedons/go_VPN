package main

import (
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
	// Load server config
	conf, err := config.LoadClientConfig("configs/server-config.yaml") 
	if err != nil {
		log.Fatalf("Failed to load server config: %v", err)
	}

	// Create TUN interface
	iface, err := tun.CreateTUNInterface(conf.TUNName)
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	// Start UDP listener
	addr := net.UDPAddr{
		IP:   net.ParseIP(conf.ServerIp),
		Port: conf.ServerPort,
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Failed to start UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("VPN server listening on %s:%d", conf.ServerIp, conf.ServerPort)

	// Init encryption
	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		log.Fatalf("Failed to initialize cipher: %v", err)
	}

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down VPN server...")
		os.Exit(0)
	}()

	clientAddr := &net.UDPAddr{}

	// Read from client -> decrypt -> write to TUN
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("Error reading from client: %v", err)
				continue
			}
			clientAddr = addr // save latest client addr

			dec, err := cipher.Decrypt(buf[:n])
			if err != nil {
				log.Printf("Decrypt error: %v", err)
				continue
			}

			_, err = iface.Write(dec)
			if err != nil {
				log.Printf("Error writing to TUN: %v", err)
			}
		}
	}()

	// Read from TUN -> encrypt -> send to client
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
		if clientAddr.IP != nil {
			_, _ = conn.WriteToUDP(enc, clientAddr)
		}
	}
}
