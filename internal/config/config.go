package config

import (
	"gopkg.in/yaml.v2"
	"os"
)

type ClientConfig struct {
	ServerIp   string `yaml:"server_ip"`
	ServerPort int    `yaml:"server_port"`
	PSK		string `yaml:"psk"`
	TUNName    string `yaml:"tun_name"`
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var conf ClientConfig
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
