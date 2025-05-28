# goVPN

goVPN is a lightweight, high-performance VPN server and client written in Go. It aims to provide secure, fast, and easy-to-use VPN connectivity for developers and end-users.

## Features

- Simple configuration and deployment
- Secure encryption using modern cryptographic standards
- Cross-platform support
- Minimal dependencies
- CLI for server and client management

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/gedons/go_VPN.git
    cd go_VPN
    ```

2. **Build the project:**
    ```sh
    go build -o go_vpn ./cmd/go_vpn
    ```

## Usage

### Start the Server

```sh
./go_vpn server --config server-config.yaml
```

### Start the Client

```sh
./go_vpn client --config client-config.yaml
```

## Configuration

Edit the provided `server-config.yaml` and `client-config.yaml` files to suit your environment.

## Contributing

Contributions are welcome! Please open issues or submit pull requests.

## License

This project is licensed under the MIT License.