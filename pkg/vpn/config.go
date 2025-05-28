package vpn

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config holds settings for both client and server modes.
type Config struct {
	Mode          string `yaml:"mode"`            // "client" or "server"
	ServerAddress string `yaml:"server_address"`  // e.g. "203.0.113.10:51820" or "0.0.0.0:51820"
	PSK           string `yaml:"psk"`
	AdapterName   string `yaml:"adapter_name"`     // e.g. "GoVPN-Client"
	AdapterIPCIDR string `yaml:"adapter_ip_cidr"`  // e.g. "10.0.0.2/24"
}

// LoadConfig reads a YAML file into Config.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	// Basic validation
	switch cfg.Mode {
	case "client", "server":
	default:
		return Config{}, fmt.Errorf("invalid mode %q: must be 'client' or 'server'", cfg.Mode)
	}
	if cfg.ServerAddress == "" {
		return Config{}, fmt.Errorf("server_address is required")
	}
	if cfg.PSK == "" {
		return Config{}, fmt.Errorf("psk is required")
	}
	if cfg.AdapterName == "" {
		return Config{}, fmt.Errorf("adapter_name is required")
	}
	if cfg.AdapterIPCIDR == "" {
		return Config{}, fmt.Errorf("adapter_ip_cidr is required")
	}
	return cfg, nil
}
