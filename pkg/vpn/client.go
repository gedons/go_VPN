package vpn

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gedons/go_VPN/internal/crypto"
	"github.com/gedons/go_VPN/internal/tun"
)

// Client implements the VPN client.
type Client struct {
	cfg     Config
	cipher  *crypto.Cipher
	tunMgr  *tun.WintunManager
	udpConn net.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewClient constructs a Client.
func NewClient(cfg Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{cfg: cfg, ctx: ctx, cancel: cancel}
}

// Start brings up the tunnel, crypto, and forwards packets.
func (c *Client) Start() error {
	// Crypto
	ci, err := crypto.NewCipher([]byte(c.cfg.PSK))
	if err != nil {
		return fmt.Errorf("crypto init: %w", err)
	}
	c.cipher = ci

	// TUN
	tm, err := tun.SetupWintun(c.ctx, c.cfg.AdapterName, c.cfg.AdapterIPCIDR)
	if err != nil {
		return fmt.Errorf("tunnel setup: %w", err)
	}
	c.tunMgr = tm

	// UDP
	conn, err := net.Dial("udp", c.cfg.ServerAddress)
	if err != nil {
		c.tunMgr.Close()
		return fmt.Errorf("udp dial: %w", err)
	}
	c.udpConn = conn

	// Forward loops
	c.wg.Add(2)
	go c.loopTunToUDP()
	go c.loopUDPToTun()
	return nil
}

// Stop tears everything down.
func (c *Client) Stop() {
	c.cancel()
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	if c.tunMgr != nil {
		c.tunMgr.Close()
	}
	c.wg.Wait()
}

func (c *Client) loopTunToUDP() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		pkt, err := c.tunMgr.ReadPacket()
		if err != nil {
			continue
		}
		enc, _ := c.cipher.Encrypt(pkt)
		c.udpConn.Write(enc)
	}
}

func (c *Client) loopUDPToTun() {
	defer c.wg.Done()
	buf := make([]byte, 65536)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		n, err := c.udpConn.Read(buf)
		if err != nil {
			continue
		}
		dec, _ := c.cipher.Decrypt(buf[:n])
		c.tunMgr.WritePacket(dec)
	}
}
