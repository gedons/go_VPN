package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gedons/go_VPN/pkg/vpn"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: gocli <config.yaml>")
		os.Exit(1)
	}
	path := os.Args[1]

	cfg, err := vpn.LoadConfig(path)
	if err != nil {
		fmt.Printf("Config error: %v\n", err)
		os.Exit(1)
	}

	switch cfg.Mode {
	case "client":
		client := vpn.NewClient(cfg)
		if err := client.Start(); err != nil {
			fmt.Printf("Client start error: %v\n", err)
			os.Exit(1)
		}
		waitForQuit()
		client.Stop()

	case "server":
		server := vpn.NewServer(cfg)
		if err := server.Start(); err != nil {
			fmt.Printf("Server start error: %v\n", err)
			os.Exit(1)
		}
		waitForQuit()
		server.Stop()
	}
}

func waitForQuit() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
