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
	conf, err := config.LoadConfig("configs/client-config.yaml")
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}

	// Setup Wintun adapter & session
	adapter, session, err := tun.SetupWintun(conf.AdapterName, conf.AdapterIPCIDR)
	if err != nil {
		log.Fatalf("Wintun setup error: %v", err)
	}
	defer adapter.Close()
	defer session.End()

	// Dial UDP to server
	serverAddr := net.JoinHostPort(conf.ServerIP, fmt.Sprintf("%d", conf.ServerPort))
	udpConn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Fatalf("UDP dial error: %v", err)
	}
	defer udpConn.Close()
	log.Printf("Connected to VPN server %s\n", serverAddr)

	// Init cipher
	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		log.Fatalf("Cipher init error: %v", err)
	}

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Stopping client...")
		os.Exit(0)
	}()

	// Tunnel: Adapter → UDP
	go func() {
		for {
			packet, err := tun.ReadPacket(session)
			if err != nil {
				log.Printf("ReadPacket error: %v", err)
				continue
			}
			enc, err := cipher.Encrypt(packet)
			if err != nil {
				log.Printf("Encrypt error: %v", err)
				continue
			}
			if _, err := udpConn.Write(enc); err != nil {
				log.Printf("UDP write error: %v", err)
			}
		}
	}()

	// Tunnel: UDP → Adapter
	buf := make([]byte, 65536)
	for {
		n, err := udpConn.Read(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}
		dec, err := cipher.Decrypt(buf[:n])
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}
		if err := tun.WritePacket(session, dec); err != nil {
			log.Printf("WritePacket error: %v", err)
		}
	}
}
