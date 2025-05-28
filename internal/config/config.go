package config

import (
	"gopkg.in/yaml.v2"
	"os"
)

type CommonConfig struct {
	ServerIP      string `yaml:"server_ip"`
	ServerPort    int    `yaml:"server_port"`
	PSK           string `yaml:"psk"`
	AdapterName   string `yaml:"adapter_name"`
	AdapterIPCIDR string `yaml:"adapter_ip_cidr"` // e.g. "10.0.0.2/24"
}

func LoadConfig(path string) (*CommonConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf CommonConfig
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}
