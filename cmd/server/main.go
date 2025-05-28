package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/gedons/go_VPN/internal/config"
	"github.com/gedons/go_VPN/internal/crypto"
	"github.com/gedons/go_VPN/internal/tun"
)

const (
	BufferSize            = 1 << 16 // 64KB
	MetricsInterval       = 30 * time.Second
	ClientTimeoutDuration = 5 * time.Minute
)

type ClientInfo struct {
	addr       *net.UDPAddr
	lastSeen   time.Time
	packetsSent uint64
	packetsRecv uint64
}

type VPNServer struct {
	config      *config.Config
	tunManager  *tun.WintunManager
	udpConn     *net.UDPConn
	cipher      *crypto.Cipher
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	clients     map[string]*ClientInfo
	clientsMu   sync.RWMutex
}

func main() {
	// Set up logging to show more detail
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	fmt.Println("=== GoVPN Server Starting ===")
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Working Directory: %s\n", getCurrentDir())
	
	// Check if running as administrator (Windows)
	if runtime.GOOS == "windows" {
		if !isRunningAsAdmin() {
			fmt.Println("WARNING: Server may need to run as Administrator for Wintun operations")
		} else {
			fmt.Println("Running as Administrator: OK")
		}
	}

	server := &VPNServer{
		clients: make(map[string]*ClientInfo),
	}
	
	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC: %v", r)
			fmt.Printf("Server crashed with panic: %v\n", r)
			waitForInput()
		}
	}()
	
	if err := server.run(); err != nil {
		log.Printf("Server failed: %v", err)
		fmt.Printf("Server failed with error: %v\n", err)
		waitForInput()
		os.Exit(1)
	}
	
	fmt.Println("Server shutdown complete")
	waitForInput()
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return dir
}

func isRunningAsAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	
	// Simple check - try to create a file in system directory
	testFile := `C:\Windows\Temp\govpn_admin_test`
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

func waitForInput() {
	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}

func (s *VPNServer) run() error {
	fmt.Println("\n=== Loading Configuration ===")
	
	// Load configuration with detailed error reporting
	conf, err := config.LoadConfig("configs/server-config.yaml")
	if err != nil {
		// Try alternative paths
		fmt.Printf("Failed to load from configs/server-config.yaml: %v\n", err)
		fmt.Println("Trying alternative config locations...")
		
		// Try current directory
		conf, err = config.LoadConfig("server-config.yaml")
		if err != nil {
			fmt.Printf("Failed to load from server-config.yaml: %v\n", err)
			
			// List available files for debugging
			listConfigFiles()
			return fmt.Errorf("config load error - tried multiple locations: %w", err)
		}
	}
	
	s.config = conf
	fmt.Printf("Configuration loaded: %s\n", conf.String())

	// Create context for graceful shutdown
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.cancel()

	// Setup signal handling
	s.setupSignalHandling()

	fmt.Println("\n=== Initializing Crypto ===")
	// Initialize cipher
	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		return fmt.Errorf("cipher init error: %w", err)
	}
	s.cipher = cipher
	fmt.Println("Crypto initialized successfully")

	fmt.Println("\n=== Setting up Tunnel ===")
	// Setup tunnel
	if err := s.setupTunnel(); err != nil {
		return fmt.Errorf("tunnel setup error: %w", err)
	}
	defer s.cleanup()
	fmt.Println("Tunnel setup completed")

	fmt.Println("\n=== Setting up UDP Listener ===")
	// Setup UDP listener
	if err := s.setupUDPListener(); err != nil {
		return fmt.Errorf("UDP setup error: %w", err)
	}
	fmt.Println("UDP listener setup completed")

	fmt.Println("\n=== Starting Packet Forwarding ===")
	// Start packet forwarding
	s.startPacketForwarding()

	// Start metrics and cleanup routines
	s.startMetricsReporting()
	s.startClientCleanup()

	fmt.Println("=== Server is now running ===")
	fmt.Println("Press Ctrl+C to shutdown gracefully")

	// Wait for shutdown
	s.wg.Wait()
	log.Println("Server shutdown complete")
	return nil
}

func listConfigFiles() {
	fmt.Println("\nAvailable files in current directory:")
	files, err := os.ReadDir(".")
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		return
	}
	
	for _, file := range files {
		if !file.IsDir() {
			fmt.Printf("  - %s\n", file.Name())
		}
	}
	
	fmt.Println("\nAvailable files in configs directory:")
	files, err = os.ReadDir("configs")
	if err != nil {
		fmt.Printf("Error reading configs directory: %v (directory may not exist)\n", err)
		return
	}
	
	for _, file := range files {
		if !file.IsDir() {
			fmt.Printf("  - configs/%s\n", file.Name())
		}
	}
}

func (s *VPNServer) setupSignalHandling() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		sig := <-sigs
		log.Printf("Shutdown signal received (%v), gracefully shutting down...", sig)
		fmt.Printf("\nShutdown signal received (%v), gracefully shutting down...\n", sig)
		s.cancel()
	}()
}

func (s *VPNServer) setupTunnel() error {
	fmt.Printf("Creating Wintun adapter: %s\n", s.config.AdapterName)
	fmt.Printf("Adapter IP CIDR: %s\n", s.config.AdapterIPCIDR)
	
	tunManager, err := tun.SetupWintun(s.ctx, s.config.AdapterName, s.config.AdapterIPCIDR)
	if err != nil {
		return fmt.Errorf("wintun setup failed: %w", err)
	}
	s.tunManager = tunManager
	
	fmt.Println("Tunnel created successfully")
	return nil
}

func (s *VPNServer) setupUDPListener() error {
	fmt.Printf("Setting up UDP listener on %s:%d\n", s.config.ServerIP, s.config.ServerPort)
	
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP(s.config.ServerIP),
		Port: s.config.ServerPort,
	}
	
	if udpAddr.IP == nil {
		return fmt.Errorf("invalid server IP address: %s", s.config.ServerIP)
	}
	
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s:%d - %w", s.config.ServerIP, s.config.ServerPort, err)
	}
	
	s.udpConn = udpConn
	fmt.Printf("Server listening on %s:%d\n", s.config.ServerIP, s.config.ServerPort)
	return nil
}

func (s *VPNServer) startPacketForwarding() {
	// UDP to TUN forwarding
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("UDP to TUN forwarding panic: %v", r)
			}
		}()
		s.forwardUDPToTun()
	}()

	// TUN to UDP forwarding
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("TUN to UDP forwarding panic: %v", r)
			}
		}()
		s.forwardTunToUDP()
	}()
}

func (s *VPNServer) forwardUDPToTun() {
	log.Println("Starting UDP to TUN forwarding")
	buf := make([]byte, BufferSize)
	
	for {
		select {
		case <-s.ctx.Done():
			log.Println("UDP to TUN forwarding stopped")
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Update client info
		s.updateClient(addr)

		dec, err := s.cipher.Decrypt(buf[:n])
		if err != nil {
			log.Printf("Decrypt error from %s: %v", addr, err)
			continue
		}

		if err := s.tunManager.WritePacket(dec); err != nil {
			log.Printf("TUN write error: %v", err)
		}
	}
}

func (s *VPNServer) forwardTunToUDP() {
	log.Println("Starting TUN to UDP forwarding")
	
	for {
		select {
		case <-s.ctx.Done():
			log.Println("TUN to UDP forwarding stopped")
			return
		default:
		}

		packet, err := s.tunManager.ReadPacket()
		if err != nil {
			log.Printf("TUN read error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		enc, err := s.cipher.Encrypt(packet)
		if err != nil {
			log.Printf("Encrypt error: %v", err)
			continue
		}

		// Send to all active clients
		s.broadcastToClients(enc)
	}
}

func (s *VPNServer) updateClient(addr *net.UDPAddr) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	
	key := addr.String()
	if client, exists := s.clients[key]; exists {
		client.lastSeen = time.Now()
		client.packetsRecv++
	} else {
		s.clients[key] = &ClientInfo{
			addr:        addr,
			lastSeen:    time.Now(),
			packetsRecv: 1,
		}
		log.Printf("New client connected: %s", addr)
		fmt.Printf("New client connected: %s\n", addr)
	}
}

func (s *VPNServer) broadcastToClients(data []byte) {
	s.clientsMu.RLock()
	clients := make([]*ClientInfo, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.clientsMu.RUnlock()

	for _, client := range clients {
		if _, err := s.udpConn.WriteToUDP(data, client.addr); err != nil {
			log.Printf("UDP write error to %s: %v", client.addr, err)
		} else {
			s.clientsMu.Lock()
			client.packetsSent++
			s.clientsMu.Unlock()
		}
	}
}

func (s *VPNServer) startClientCleanup() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.cleanupStaleClients()
			}
		}
	}()
}

func (s *VPNServer) cleanupStaleClients() {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	
	now := time.Now()
	for key, client := range s.clients {
		if now.Sub(client.lastSeen) > ClientTimeoutDuration {
			log.Printf("Removing stale client: %s", client.addr)
			delete(s.clients, key)
		}
	}
}

func (s *VPNServer) startMetricsReporting() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(MetricsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.reportMetrics()
			}
		}
	}()
}

func (c *VPNServer) reportMetrics() {
	log.Println("Metrics reporting disabled (no metrics available in WintunManager)")
}


func (s *VPNServer) cleanup() {
	fmt.Println("Cleaning up resources...")
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tunManager != nil {
		s.tunManager.Close()
	}
}