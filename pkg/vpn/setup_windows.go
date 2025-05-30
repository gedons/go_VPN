//go:build windows

package vpn

import (
	"fmt"
	"os/exec"
)

// SetupWindowsClient applies Windows-specific routing for VPN client.
func SetupWindowsClient(adapterName, nextHop string) error {
	fmt.Println("[Windows Client Setup]")

	// Add default route through VPN interface
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$iface = Get-NetAdapter -Name '%s'; if (!$iface) { Write-Error "Adapter '%s' not found"; exit 1 }; New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $iface.ifIndex -NextHop "%s" -RouteMetric 1 -ErrorAction Stop`, adapterName, adapterName, nextHop),
	)
	output, err := cmd.CombinedOutput()
	fmt.Println(string(output))
	if err != nil {
		return fmt.Errorf("client setup failed: %w", err)
	}
	return nil
}

// SetupWindowsServer configures the firewall and enables IP forwarding.
func SetupWindowsServer(adapterName string, port int) error {
	fmt.Println("[Windows Server Setup]")

	// Enable IP forwarding
	cmd := exec.Command("powershell", "-Command",
		`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1`,
	)
	output, err := cmd.CombinedOutput()
	fmt.Println(string(output))
	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Add firewall rule for UDP port
	cmd = exec.Command("powershell", "-Command",
		fmt.Sprintf(`New-NetFirewallRule -DisplayName "GoVPN UDP %d" -Direction Inbound -Protocol UDP -LocalPort %d -Action Allow -EdgeTraversalPolicy Allow -Profile Any`, port, port),
	)
	output, _ = cmd.CombinedOutput()
	fmt.Println(string(output))
	// Ignore error if rule already exists
	return nil
}
