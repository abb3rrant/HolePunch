# HolePunch

A UDP hole punching VPN-like tool for establishing peer-to-peer connections through NAT.

## Overview

HolePunch consists of two components:

1. **Orchestration Server** - Coordinates connections between clients by facilitating UDP hole punching
2. **Client** - Connects to the server and establishes encrypted P2P connections with other clients

## How It Works

1. Clients register with the orchestration server via UDP on a high ephemeral port
2. The server tracks all registered clients and their public IP:port mappings
3. When a client wants to connect to another, both clients simultaneously send UDP packets to each other's public addresses
4. This "punches holes" through NAT firewalls, allowing direct P2P communication
5. All peer-to-peer communication is encrypted using XChaCha20-Poly1305 with X25519 key exchange

## Building

```bash
# Build both server and client
make build

# Build server only
make server

# Build client only
make client

# Build for all platforms
make release
```

Binaries are output to the `bin/` directory.

## Usage

### Start the Server

```bash
# Default: listen on 0.0.0.0:41234
./bin/holepunch-server

# Custom port
./bin/holepunch-server -port 51234

# Custom bind address
./bin/holepunch-server -bind 192.168.1.100 -port 41234
```

### Start a Client

```bash
# Connect to local server
./bin/holepunch-client -server localhost:41234

# Connect to remote server
./bin/holepunch-client -server example.com:41234
```

### Client Commands

Once the client is running, you can use these interactive commands:

- `peers` - List all discovered peers
- `connect <id>` - Initiate hole punching to a peer (use ID prefix)
- `send <id> <message>` - Send an encrypted message to a connected peer
- `quit` - Exit the client

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestration Server                      │
│                      (Public IP)                             │
└─────────────────────┬───────────────────┬───────────────────┘
                      │                   │
              Register│                   │Register
                      │                   │
              ┌───────▼───────┐   ┌───────▼───────┐
              │   NAT/FW A    │   │   NAT/FW B    │
              └───────┬───────┘   └───────┬───────┘
                      │                   │
              ┌───────▼───────┐   ┌───────▼───────┐
              │   Client A    │◄─►│   Client B    │
              │  (Private)    │   │  (Private)    │
              └───────────────┘   └───────────────┘
                        ▲                   ▲
                        └───────────────────┘
                         Direct P2P (after punch)
```

## Protocol

### Message Types

| Type | Name | Description |
|------|------|-------------|
| 1 | Register | Client registration with server |
| 2 | RegisterAck | Server acknowledgment |
| 3 | PeerList | List of available peers |
| 4 | PunchRequest | Request to punch to a peer |
| 5 | PunchInit | Server instructing punch initiation |
| 6 | PunchAck | Acknowledgment of punch |
| 7 | Data | Encrypted data packet |
| 8 | Keepalive | Connection keepalive |
| 9 | KeyExchange | X25519 public key exchange |
| 10 | Disconnect | Client disconnecting |

### Encryption

- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Symmetric Encryption**: XChaCha20-Poly1305
- Each peer connection has its own derived encryption key

## Security Considerations

- All peer-to-peer traffic is encrypted
- Server only sees encrypted traffic metadata (IPs, ports)
- Forward secrecy provided by ephemeral key pairs per session
- No authentication mechanism yet - any client can register

## Project Structure

```
HolePunch/
├── cmd/
│   ├── server/        # Orchestration server
│   │   └── main.go
│   └── client/        # HolePunch client
│       └── main.go
├── pkg/
│   ├── holepunch/     # Hole punching and crypto
│   │   ├── crypto.go
│   │   └── puncher.go
│   └── protocol/      # Wire protocol
│       └── protocol.go
├── Makefile
├── go.mod
└── README.md
```

## License

MIT
