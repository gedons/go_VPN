package tun

import (
	"context"
	"log"
	"net/netip"
	"time"

	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	SessionRingBuffer = 1 << 23 // 8 MiB
	IPStabilizeDelay  = 300 * time.Millisecond
)

// WintunManager wraps the adapter and session.
type WintunManager struct {
	adapter *wintun.Adapter
	session *wintun.Session
}

// SetupWintun creates/opens the adapter, assigns IP, and starts session.
func SetupWintun(ctx context.Context, adapterName, cidr string) (*WintunManager, error) {
	// 1) Create or open
	a, err := wintun.CreateAdapter(adapterName, "GoVPN", nil)
	if err != nil {
		log.Printf("CreateAdapter failed: %v; trying OpenAdapter", err)
		a, err = wintun.OpenAdapter(adapterName)
		if err != nil {
			return nil, err
		}
	}
	log.Printf("Adapter LUID %d ready", a.LUID())

	// 2) Assign IP via winipcfg
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		a.Close()
		return nil, err
	}
	luid := winipcfg.LUID(a.LUID())
	if err := luid.SetIPAddresses([]netip.Prefix{pfx}); err != nil {
		a.Close()
		return nil, err
	}
	log.Printf("Assigned IP %s", cidr)
	time.Sleep(IPStabilizeDelay)

	// 3) Start session
	sess, err := a.StartSession(SessionRingBuffer)
	if err != nil {
		a.Close()
		return nil, err
	}
	log.Printf("Session started (ring=%d)", SessionRingBuffer)

	return &WintunManager{adapter: a, session: &sess}, nil
}

// ReadPacket returns one packet or an error.
func (m *WintunManager) ReadPacket() ([]byte, error) {
	pkt, err := (*m.session).ReceivePacket()
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(pkt))
	copy(data, pkt)
	(*m.session).ReleaseReceivePacket(pkt)
	return data, nil
}

// WritePacket sends one packet.
func (m *WintunManager) WritePacket(data []byte) error {
	(*m.session).SendPacket(data)
	return nil
}

// Close tears down session and adapter.
func (m *WintunManager) Close() {
	if m.session != nil {
		(*m.session).End()
	}
	if m.adapter != nil {
		m.adapter.Close()
	}
}
