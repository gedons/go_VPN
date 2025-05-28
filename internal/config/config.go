//internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	ServerIP       string `yaml:"server_ip" json:"server_ip"`
	ServerPort     int    `yaml:"server_port" json:"server_port"`
	PSK            string `yaml:"psk" json:"psk"`
	AdapterName    string `yaml:"adapter_name" json:"adapter_name"`
	AdapterIPCIDR  string `yaml:"adapter_ip_cidr" json:"adapter_ip_cidr"`
}

// LoadConfig loads configuration from a YAML file with validation
func LoadConfig(configPath string) (*Config, error) {
	// Validate file path
	if strings.TrimSpace(configPath) == "" {
		return nil, fmt.Errorf("config path cannot be empty")
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file does not exist: %s", configPath)
	}

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config %s: %w", configPath, err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration in %s: %w", configPath, err)
	}

	// Log successful load
	fmt.Printf("Configuration loaded successfully from %s\n", configPath)
	return &config, nil
}

// Validate performs comprehensive validation of the configuration
func (c *Config) Validate() error {
	var errors []string

	// Validate ServerIP
	if strings.TrimSpace(c.ServerIP) == "" {
		errors = append(errors, "server_ip cannot be empty")
	}

	// Validate ServerPort
	if c.ServerPort <= 0 || c.ServerPort > 65535 {
		errors = append(errors, "server_port must be between 1 and 65535")
	}

	// Validate PSK
	psk := strings.TrimSpace(c.PSK)
	if psk == "" {
		errors = append(errors, "psk cannot be empty")
	} else if len(psk) < 16 {
		errors = append(errors, "psk must be at least 16 characters long for security")
	} else if len(psk) > 64 {
		errors = append(errors, "psk cannot be longer than 64 characters")
	}

	// Validate AdapterName
	if strings.TrimSpace(c.AdapterName) == "" {
		errors = append(errors, "adapter_name cannot be empty")
	}

	// Validate AdapterIPCIDR
	if strings.TrimSpace(c.AdapterIPCIDR) == "" {
		errors = append(errors, "adapter_ip_cidr cannot be empty")
	} else {
		// Basic CIDR format validation
		if !strings.Contains(c.AdapterIPCIDR, "/") {
			errors = append(errors, "adapter_ip_cidr must be in CIDR format (e.g., 10.0.0.1/24)")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// GetConfigDir returns the directory containing configuration files
func GetConfigDir() (string, error) {
	// Try current directory first
	if _, err := os.Stat("configs"); err == nil {
		return "configs", nil
	}

	// Try executable directory
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	configDir := filepath.Join(filepath.Dir(execPath), "configs")
	if _, err := os.Stat(configDir); err == nil {
		return configDir, nil
	}

	// Return current directory as fallback
	return "configs", nil
}

// LoadClientConfig is a convenience function for loading client configuration
func LoadClientConfig() (*Config, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return nil, err
	}
	
	configPath := filepath.Join(configDir, "client-config.yaml")
	return LoadConfig(configPath)
}

// LoadServerConfig is a convenience function for loading server configuration
func LoadServerConfig() (*Config, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return nil, err
	}
	
	configPath := filepath.Join(configDir, "server-config.yaml")
	return LoadConfig(configPath)
}

// SaveConfig saves the configuration to a YAML file
func (c *Config) SaveConfig(configPath string) error {
	// Validate configuration before saving
	if err := c.Validate(); err != nil {
		return fmt.Errorf("cannot save invalid configuration: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", configPath, err)
	}

	fmt.Printf("Configuration saved to %s\n", configPath)
	return nil
}

// String returns a string representation of the config (without exposing PSK)
func (c *Config) String() string {
	return fmt.Sprintf("Config{ServerIP: %s, ServerPort: %d, AdapterName: %s, AdapterIPCIDR: %s, PSK: [REDACTED]}",
		c.ServerIP, c.ServerPort, c.AdapterName, c.AdapterIPCIDR)
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	return &Config{
		ServerIP:      c.ServerIP,
		ServerPort:    c.ServerPort,
		PSK:           c.PSK,
		AdapterName:   c.AdapterName,
		AdapterIPCIDR: c.AdapterIPCIDR,
	}
}

// IsClient returns true if this appears to be a client configuration
func (c *Config) IsClient() bool {
	return strings.Contains(strings.ToLower(c.AdapterName), "client")
}

// IsServer returns true if this appears to be a server configuration
func (c *Config) IsServer() bool {
	return strings.Contains(strings.ToLower(c.AdapterName), "server")
}

// GetListenAddress returns the address for server to listen on
func (c *Config) GetListenAddress() string {
	return fmt.Sprintf("%s:%d", c.ServerIP, c.ServerPort)
}

// GetDialAddress returns the address for client to dial
func (c *Config) GetDialAddress() string {
	return fmt.Sprintf("%s:%d", c.ServerIP, c.ServerPort)
}