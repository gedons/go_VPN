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
	// Load config
	conf, err := config.LoadConfig("configs/server-config.yaml")
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

	// Start UDP listener
	addr := net.UDPAddr{IP: net.ParseIP(conf.ServerIP), Port: conf.ServerPort}
	udpConn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("UDP listen error: %v", err)
	}
	defer udpConn.Close()
	log.Printf("Server listening on %s:%d\n", conf.ServerIP, conf.ServerPort)

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
		log.Println("Stopping server...")
		os.Exit(0)
	}()

	var clientAddr *net.UDPAddr

	// Tunnel: UDP → Adapter
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("UDP read error: %v", err)
				continue
			}
			clientAddr = addr
			dec, err := cipher.Decrypt(buf[:n])
			if err != nil {
				log.Printf("Decrypt error: %v", err)
				continue
			}
			if err := tun.WritePacket(session, dec); err != nil {
				log.Printf("WritePacket error: %v", err)
			}
		}
	}()

	// Tunnel: Adapter → UDP
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
		if clientAddr != nil {
			if _, err := udpConn.WriteToUDP(enc, clientAddr); err != nil {
				log.Printf("UDP write error: %v", err)
			}
		}
	}
}
