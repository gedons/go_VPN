package tun

import ( 
	"github.com/songgao/water"
	"log"
)

func CreateTUNInterface(ifName string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.InterfaceName = ifName

	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
		return nil, err
	}

	log.Printf("TUN interface %s created successfully", iface.Name())
	return iface, nil
}