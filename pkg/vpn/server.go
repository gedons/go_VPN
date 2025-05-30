package vpn

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"

	"github.com/gedons/go_VPN/internal/crypto"
	"github.com/gedons/go_VPN/internal/tun"
)

// Server implements the VPN server.
type Server struct {
	cfg     Config
	cipher  *crypto.Cipher
	tunMgr  *tun.WintunManager
	udpConn *net.UDPConn
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	clients   map[string]*net.UDPAddr
	clientsMu sync.RWMutex
}

// NewServer constructs a Server.
func NewServer(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		clients: make(map[string]*net.UDPAddr),
	}
}

// Start brings up the server tunnel and forwards packets.
func (s *Server) Start() error {
	
if runtime.GOOS == "windows" {
	port, err := s.cfg.ExtractPort()
	if err != nil {
		log.Printf("Failed to extract port from server address: %v", err)
	} else {
		if err := SetupWindowsServer(s.cfg.AdapterName, port); err != nil {
			log.Printf("Server setup warning: %v", err)
		}
	}
}

	// Crypto
	ci, err := crypto.NewCipher([]byte(s.cfg.PSK))
	if err != nil {
		return fmt.Errorf("crypto init: %w", err)
	}
	s.cipher = ci

	// TUN
	tm, err := tun.SetupWintun(s.ctx, s.cfg.AdapterName, s.cfg.AdapterIPCIDR)
	if err != nil {
		return fmt.Errorf("tunnel setup: %w", err)
	}
	s.tunMgr = tm

	// UDP listen
	addr, _ := net.ResolveUDPAddr("udp", s.cfg.ServerAddress)
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.tunMgr.Close()
		return fmt.Errorf("udp listen: %w", err)
	}
	s.udpConn = udp

	// Forward loops
	s.wg.Add(2)
	go s.loopUDPToTun()
	go s.loopTunToUDP()
	return nil
}

// Stop shuts down the server.
func (s *Server) Stop() {
	s.cancel()
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tunMgr != nil {
		s.tunMgr.Close()
	}
	s.wg.Wait()
}

func (s *Server) loopUDPToTun() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// register client
		key := addr.String()
		s.clientsMu.Lock()
		s.clients[key] = addr
		s.clientsMu.Unlock()

		dec, _ := s.cipher.Decrypt(buf[:n])
		s.tunMgr.WritePacket(dec)
	}
}

func (s *Server) loopTunToUDP() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		pkt, err := s.tunMgr.ReadPacket()
		if err != nil {
			continue
		}
		enc, _ := s.cipher.Encrypt(pkt)
		// broadcast to all
		s.clientsMu.RLock()
		for _, addr := range s.clients {
			s.udpConn.WriteToUDP(enc, addr)
		}
		s.clientsMu.RUnlock()
	}
}
