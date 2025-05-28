package tun

import (
	"log"
	"net/netip"
	"time"
	"os/exec"

	"golang.zx2c4.com/wintun"
)

// SetupWintun creates a Wintun adapter, assigns the given CIDR IP, and starts a session.
func SetupWintun(adapterName, cidr string) (*wintun.Adapter, *wintun.Session, error) {
	// 1. Create or open the adapter
	a, err := wintun.CreateAdapter(adapterName, "Wintun VPN", nil)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Wintun adapter %s created\n", adapterName)

	// 2. Set IP address
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, nil, err
	}

	// Assign IP using netsh as a workaround since LUID.SetIPAddresses does not exist
	cmd := exec.Command("netsh", "interface", "ip", "set", "address", "name="+adapterName, "static", prefix.Addr().String(), prefix.Masked().String())
	if err := cmd.Run(); err != nil {
		return nil, nil, err
	}
	log.Printf("Assigned IP %s to adapter %s\n", cidr, adapterName)

	// 3. Start the session (8 MiB ring buffer)
	sess, err := a.StartSession(1 << 23)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Wintun session started on %s\n", adapterName)

	// Wait a moment for Windows to apply the IP
	time.Sleep(500 * time.Millisecond)
	return a, &sess, nil
}

// ReadPacket blocks until a packet is available, then returns its payload.
func ReadPacket(sess *wintun.Session) ([]byte, error) {
	packet, err := sess.ReceivePacket()
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(packet))
	copy(data, packet)
	sess.ReleaseReceivePacket(packet)
	return data, nil
}

// WritePacket sends raw IP packet bytes into the session.
func WritePacket(sess *wintun.Session, data []byte) error {
	sess.SendPacket(data)
	return nil
}
