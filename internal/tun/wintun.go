package tun

import (
	"context"
	"log"
	"net/netip"
	"time"

	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// SessionRingBuffer is the size (in bytes) of the Wintun ring buffer.
const SessionRingBuffer = 1 << 23 // 8 MiB

// IPStabilizeDelay gives Windows time to apply the IP address.
const IPStabilizeDelay = 300 * time.Millisecond

// WintunManager handles the adapter and packet session.
type WintunManager struct {
	adapter *wintun.Adapter
	session *wintun.Session
}

// SetupWintun creates (or opens) a Wintun adapter named adapterName,
// assigns it the CIDR address (e.g. "10.0.0.2/24"), and starts a packet session.
func SetupWintun(ctx context.Context, adapterName, cidr string) (*WintunManager, error) {
	// 1) Create or open the adapter
	a, err := wintun.CreateAdapter(adapterName, "GoVPN", nil)
	if err != nil {
		log.Printf("CreateAdapter failed, trying OpenAdapter: %v", err)
		a, err = wintun.OpenAdapter(adapterName)
		if err != nil {
			return nil, err
		}
	}
	log.Printf("Wintun adapter with LUID %d ready", a.LUID())

	// 2) Assign IP using winipcfg (avoids UInt32 conversion issues)
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		a.Close()
		return nil, err
	}

	luid := a.LUID()
	netLUID := winipcfg.LUID(luid)
	if err := netLUID.SetIPAddresses([]netip.Prefix{prefix}); err != nil {
		a.Close()
		return nil, err
	}
	log.Printf("Assigned IP %s to adapter LUID %d", cidr, a.LUID())



	// Give Windows a moment to apply the IP
	time.Sleep(IPStabilizeDelay)

	// 3) Start a packet session
	sess, err := a.StartSession(SessionRingBuffer)
	if err != nil {
		a.Close()
		return nil, err
	}
	log.Printf("Wintun session started (ring=%d bytes)", SessionRingBuffer)

	return &WintunManager{
		adapter: a,
		session: &sess,
	}, nil
}

// ReadPacket reads one raw IP packet from the tunnel.
func (m *WintunManager) ReadPacket() ([]byte, error) {
	packet, err := (*m.session).ReceivePacket()
	if err != nil {
		// Special case: "No more data" is not a real error
		if err.Error() == "No more data is available." {
			time.Sleep(10 * time.Millisecond) // avoid tight loop
			return nil, nil
		}
		return nil, err
	}
	if packet == nil {
		time.Sleep(10 * time.Millisecond)
		return nil, nil
	}

	data := make([]byte, len(packet))
	copy(data, packet)
	(*m.session).ReleaseReceivePacket(packet)	

	return data, nil
}


// WritePacket writes one raw IP packet into the tunnel.
func (m *WintunManager) WritePacket(data []byte) error {
	(*m.session).SendPacket(data)
	return nil
}

// Close ends the session and closes the adapter.
func (m *WintunManager) Close() {
	if m.session != nil {
		(*m.session).End()
	}
	if m.adapter != nil {
		m.adapter.Close()
	}
}
