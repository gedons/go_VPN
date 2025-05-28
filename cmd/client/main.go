//client/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gedons/go_VPN/internal/config"
	"github.com/gedons/go_VPN/internal/crypto"
	"github.com/gedons/go_VPN/internal/tun"
)

const (
	ReconnectDelay    = 5 * time.Second
	MaxReconnectTries = 10
	BufferSize        = 1 << 16 // 64KB
	MetricsInterval   = 30 * time.Second
)

type VPNClient struct {
	config      *config.Config
	tunManager  *tun.WintunManager
	udpConn     net.Conn
	cipher      *crypto.Cipher
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	reconnectCh chan struct{}
}

func main() {
	// Setup logging to both console and file for debugging
	logFile, err := os.OpenFile("vpn-client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}
	
	// Also log to console
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	
	fmt.Println("=== GoVPN Client Starting ===")
	fmt.Printf("Current working directory: %s\n", getCurrentDir())
	fmt.Printf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	
	client := &VPNClient{
		reconnectCh: make(chan struct{}, 1),
	}
	
	// Use a function that won't exit immediately on error
	err = client.run()
	if err != nil {
		fmt.Printf("ERROR: Client failed: %v\n", err)
		log.Printf("Client failed: %v", err)
	} else {
		fmt.Println("Client completed successfully")
		log.Println("Client completed successfully")
	}
	
	// Always wait for user input before closing
	fmt.Println("\n=== Client Session Ended ===")
	fmt.Printf("Check vpn-client.log for detailed logs\n")
	fmt.Printf("Press Enter to exit...")
	fmt.Scanln()
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return dir
}

func (c *VPNClient) run() error {
	fmt.Println("Step 1: Loading configuration...")
	
	// Check if config file exists
	configPath := "configs/client-config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Try alternative paths
		altPaths := []string{
			"client-config.yaml",
			"../configs/client-config.yaml",
			"./configs/client-config.yaml",
		}
		
		found := false
		for _, path := range altPaths {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				found = true
				break
			}
		}
		
		if !found {
			return fmt.Errorf("config file not found. Tried paths: %s, %v", configPath, altPaths)
		}
	}
	
	fmt.Printf("Loading config from: %s\n", configPath)
	
	// Load configuration
	conf, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("config load error: %w", err)
	}
	c.config = conf
	fmt.Printf("✓ Configuration loaded successfully\n")
	fmt.Printf("  Server: %s:%d\n", conf.ServerIP, conf.ServerPort)
	fmt.Printf("  Adapter: %s (%s)\n", conf.AdapterName, conf.AdapterIPCIDR)

	fmt.Println("\nStep 2: Initializing components...")
	
	// Create context for graceful shutdown
	c.ctx, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()

	// Setup signal handling
	c.setupSignalHandling()
	fmt.Println("✓ Signal handling setup complete")

	// Initialize cipher
	fmt.Println("Initializing encryption...")
	cipher, err := crypto.NewCipher([]byte(conf.PSK))
	if err != nil {
		return fmt.Errorf("cipher init error: %w", err)
	}
	c.cipher = cipher
	fmt.Println("✓ Encryption initialized")

	// Setup tunnel
	fmt.Println("Setting up Wintun tunnel...")
	if err := c.setupTunnel(); err != nil {
		return fmt.Errorf("tunnel setup error: %w", err)
	}
	defer c.cleanup()
	fmt.Println("✓ Wintun tunnel setup complete")

	// Start connection with retry logic
	fmt.Println("\nStep 3: Connecting to VPN server...")
	if err := c.connectWithRetry(); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	fmt.Println("✓ Connected to VPN server")

	// Start packet forwarding
	fmt.Println("\nStep 4: Starting packet forwarding...")
	c.startPacketForwarding()
	fmt.Println("✓ Packet forwarding started")

	// Start metrics reporting
	fmt.Println("Starting metrics reporting...")
	c.startMetricsReporting()
	fmt.Println("✓ Metrics reporting started")

	fmt.Println("\n=== VPN CLIENT IS NOW RUNNING ===")
	fmt.Println("The VPN tunnel is active. Press Ctrl+C to stop.")
	fmt.Println("Check the log file for detailed connection information.")

	// Wait for shutdown
	c.wg.Wait()
	fmt.Println("Client shutdown complete")
	return nil
}

func (c *VPNClient) setupSignalHandling() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		sig := <-sigs
		fmt.Printf("\nShutdown signal received: %v\n", sig)
		log.Printf("Shutdown signal received: %v", sig)
		fmt.Println("Gracefully shutting down...")
		c.cancel()
	}()
}

func (c *VPNClient) setupTunnel() error {
	fmt.Printf("Creating Wintun adapter: %s\n", c.config.AdapterName)
	tunManager, err := tun.SetupWintun(c.ctx, c.config.AdapterName, c.config.AdapterIPCIDR)
	if err != nil {
		return fmt.Errorf("Wintun setup failed: %w", err)
	}
	c.tunManager = tunManager
	fmt.Printf("Wintun adapter created with IP: %s\n", c.config.AdapterIPCIDR)
	return nil
}

func (c *VPNClient) connectWithRetry() error {
	serverAddr := net.JoinHostPort(c.config.ServerIP, fmt.Sprintf("%d", c.config.ServerPort))
	fmt.Printf("Attempting to connect to server: %s\n", serverAddr)
	
	for i := 0; i < MaxReconnectTries; i++ {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		fmt.Printf("Connection attempt %d/%d to %s...\n", i+1, MaxReconnectTries, serverAddr)
		udpConn, err := net.DialTimeout("udp", serverAddr, 10*time.Second)
		if err != nil {
			fmt.Printf("❌ Connection attempt %d failed: %v\n", i+1, err)
			log.Printf("Connection attempt %d failed: %v", i+1, err)
			if i < MaxReconnectTries-1 {
				fmt.Printf("Retrying in %v...\n", ReconnectDelay)
				time.Sleep(ReconnectDelay)
				continue
			}
			return fmt.Errorf("failed to connect after %d attempts: %w", MaxReconnectTries, err)
		}

		c.udpConn = udpConn
		fmt.Printf("✓ Connected to VPN server %s\n", serverAddr)
		log.Printf("Connected to VPN server %s", serverAddr)
		return nil
	}
	return fmt.Errorf("exceeded maximum reconnection attempts")
}

func (c *VPNClient) startPacketForwarding() {
	// TUN to UDP forwarding
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.forwardTunToUDP()
	}()

	// UDP to TUN forwarding
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.forwardUDPToTun()
	}()
}

func (c *VPNClient) forwardTunToUDP() {
	fmt.Println("TUN to UDP forwarding goroutine started")
	log.Println("Starting TUN to UDP forwarding")
	
	for {
		select {
		case <-c.ctx.Done():
			fmt.Println("TUN to UDP forwarding stopped")
			log.Println("TUN to UDP forwarding stopped")
			return
		default:
		}

		packet, err := c.tunManager.ReadPacket()
		if err != nil {
			log.Printf("TUN read error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		enc, err := c.cipher.Encrypt(packet)
		if err != nil {
			log.Printf("Encrypt error: %v", err)
			continue
		}

		if _, err := c.udpConn.Write(enc); err != nil {
			log.Printf("UDP write error: %v", err)
			fmt.Printf("Connection error, may need to reconnect: %v\n", err)
			select {
			case c.reconnectCh <- struct{}{}:
			default:
			}
		}
	}
}

func (c *VPNClient) forwardUDPToTun() {
	fmt.Println("UDP to TUN forwarding goroutine started")
	log.Println("Starting UDP to TUN forwarding")
	buf := make([]byte, BufferSize)
	
	for {
		select {
		case <-c.ctx.Done():
			fmt.Println("UDP to TUN forwarding stopped")
			log.Println("UDP to TUN forwarding stopped")
			return
		default:
		}

		// Set read timeout
		c.udpConn.SetReadDeadline(time.Now().Add(time.Second))
		
		n, err := c.udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("UDP read error: %v", err)
			continue
		}

		dec, err := c.cipher.Decrypt(buf[:n])
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}

		if err := c.tunManager.WritePacket(dec); err != nil {
			log.Printf("TUN write error: %v", err)
		}
	}
}

func (c *VPNClient) startMetricsReporting() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(MetricsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.reportMetrics()
			}
		}
	}()
}

func (c *VPNClient) reportMetrics() {
	log.Println("Metrics reporting disabled (no metrics available in WintunManager)")
}


func (c *VPNClient) cleanup() {
	fmt.Println("Cleaning up resources...")
	if c.udpConn != nil {
		c.udpConn.Close()
		fmt.Println("✓ UDP connection closed")
	}
	if c.tunManager != nil {
		c.tunManager.Close()
		fmt.Println("✓ Wintun tunnel closed")
	}
}