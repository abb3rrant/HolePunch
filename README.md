# HolePunch

A UDP hole punching pivoting tool for establishing encrypted peer-to-peer tunnels through NAT. Route traffic through a connected agent into their local network -- similar to ligolo-ng, but using direct P2P connections instead of a relay server.

## Overview

HolePunch consists of two components:

1. **Orchestration Server** - Coordinates connections between clients by facilitating UDP hole punching. Only handles signaling; all data flows directly between peers.
2. **Client** - Connects to the server, establishes encrypted P2P connections with other clients, and provides SOCKS5 proxy, TCP port forwarding, and TUN-based routing to reach networks behind the remote peer.

## How It Works

1. Clients register with the orchestration server via UDP
2. The server tracks all registered clients and broadcasts peer lists
3. When a client wants to connect to another, the server sends both clients each other's public IP:port
4. Both clients simultaneously send UDP packets to each other's public addresses, punching through NAT
5. After the hole is punched, an X25519 key exchange establishes a shared secret
6. All subsequent P2P traffic is encrypted with XChaCha20-Poly1305
7. The operator can then route traffic through the tunnel using SOCKS5, port forwarding, or a TUN interface

## Building

```bash
# Build both server and client
make build

# Build server only
make server

# Build client only
make client

# Build for all platforms (linux/darwin/windows, amd64/arm64)
make release

# Run tests
make test
```

Binaries are output to the `bin/` directory.

### Build with version info

```bash
go build -ldflags "-X github.com/abb3rrant/HolePunch/pkg/config.Version=1.0.0 \
  -X github.com/abb3rrant/HolePunch/pkg/config.Commit=$(git rev-parse --short HEAD) \
  -X github.com/abb3rrant/HolePunch/pkg/config.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/holepunch-client ./cmd/client
```

## Usage

### Start the Server

```bash
# Default: listen on 0.0.0.0:41234
./bin/holepunch-server

# Custom port and bind address
./bin/holepunch-server -port 51234 -bind 192.168.1.100

# IPv6
./bin/holepunch-server -6

# Limit connected clients
./bin/holepunch-server -max-clients 10

# Print version
./bin/holepunch-server -version
```

### Start a Client

```bash
# Connect to local server
./bin/holepunch-client -server localhost:41234

# Connect to remote server
./bin/holepunch-client -server example.com:41234

# IPv6
./bin/holepunch-client -6 -server [::1]:41234

# Print version
./bin/holepunch-client -version
```

### Client Commands

Once the client is running, an interactive REPL provides the following commands:

#### Peer Management

| Command | Description |
|---------|-------------|
| `agents` | List all discovered agents and their connection status |
| `session <id>` | Select an agent for tunneling (uses ID prefix matching) |
| `session` | Show current session |
| `connect <id>` | Alias for `session` (backward compatible) |
| `send <id> <msg>` | Send a text message to a connected peer |

#### TUN Interface (Linux only, requires root)

| Command | Description |
|---------|-------------|
| `tunnel start` | Create TUN device and bring it up |
| `tunnel stop` | Tear down TUN device and remove all routes |
| `route add <cidr>` | Route a network through the tunnel (adds AllowedIP + OS route) |
| `route del <cidr>` | Remove a route |
| `route list` | Show active routes and their associated peers |
| `ifconfig` | Show tunnel interface info, peer endpoint, and AllowedIPs |

#### TCP Port Forwarding (all platforms, no root)

| Command | Description |
|---------|-------------|
| `listener add <local>:<remote>` | Forward a local TCP port to a remote address via the agent |
| `listener del <port>` | Remove a listener |
| `listener list` | Show active listeners |

Example: `listener add 8080:192.168.1.10:80` binds local port 8080 and forwards connections through the agent to 192.168.1.10:80.

#### SOCKS5 Proxy (all platforms, no root)

| Command | Description |
|---------|-------------|
| `socks start [port]` | Start a SOCKS5 proxy (default port: 1080) |
| `socks stop` | Stop the SOCKS5 proxy |

Once running, use with:
```bash
curl --socks5 127.0.0.1:1080 http://target
proxychains nmap -sT target
```

#### Info

| Command | Description |
|---------|-------------|
| `stats` | Show connection statistics (bytes, packets, streams, uptime) |
| `version` | Show version, Go version, and OS/arch |
| `help` | Show command reference |
| `quit` | Clean shutdown (tears down tunnels, notifies server) |

### Example Workflow

```
# 1. Operator starts client, discovers agent
> agents
  a1b2c3d4 - 203.0.113.50:41234 (connected)

# 2. Select agent
> session a1b2

# 3a. Option A: SOCKS5 proxy (easiest, all platforms)
> socks start
SOCKS5 started: 127.0.0.1:1080
  $ proxychains nmap -sT 10.0.0.0/24

# 3b. Option B: Port forwarding (specific services)
> listener add 2222:10.0.0.5:22
Listener: 127.0.0.1:2222 -> 10.0.0.5:22
  $ ssh -p 2222 127.0.0.1

# 3c. Option C: TUN interface (Linux, full IP routing)
> tunnel start
> route add 10.0.0.0/24
  $ nmap -sT 10.0.0.0/24
```

## Architecture

```
                    Orchestration Server
                      (Public IP)
                     /             \
             Register               Register
                   /                 \
           +------+------+   +-------+------+
           |  NAT/FW A   |   |   NAT/FW B   |
           +------+------+   +-------+------+
                  |                   |
           +------+------+   +-------+------+
           |  Operator   |<->|    Agent     |
           |  (Client)   |   |   (Client)   |
           +-------------+   +--------------+
                    ^                   ^
                    +-------------------+
                     Encrypted P2P tunnel
                     (XChaCha20-Poly1305)
```

Traffic flow through the tunnel:

```
[Operator tool] -> [SOCKS5/Listener/TUN] -> [Encrypted P2P] -> [Agent] -> [Target network]
```

## Protocol

### Wire Protocol (Server <-> Client)

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

### Proxy Protocol (Peer <-> Peer, inside encrypted Data messages)

| Type | Value | Description |
|------|-------|-------------|
| TCPConnect | 20 | Open TCP connection request |
| TCPConnectAck | 21 | Connection established |
| TCPData | 22 | TCP payload relay |
| TCPClose | 23 | Connection teardown |
| TCPError | 24 | Error report |
| UDPData | 25 | UDP datagram |
| IPPacket | 30 | Raw IP packet (TUN mode) |

### Encryption

- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Symmetric Encryption**: XChaCha20-Poly1305 (AEAD)
- **Nonces**: Counter-based (first 8 bytes counter, remaining 16 random)
- Each peer connection derives its own encryption key via ECDH

### Security Features

- **Replay protection**: Sliding bitmap window (2048 sequence numbers) rejects duplicate or replayed packets
- **Counter-based nonces**: Monotonically increasing counters prevent nonce reuse
- **Session expiry**: Automatic rekey signaling at 120s, hard reject at 180s
- **Silent mode**: Unknown/unauthenticated packets are silently dropped (no information leakage)
- **Cryptokey routing**: WireGuard-style AllowedIPs ensures packets are only forwarded to authorized peers
- **Endpoint roaming**: Peer addresses auto-update on receipt of authenticated packets (NAT rebinding support)
- **Forward secrecy**: Ephemeral key pairs generated per session

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Server | Yes | Yes | Yes |
| Client REPL | Yes | Yes | Yes |
| SOCKS5 proxy | Yes | Yes | Yes |
| TCP port forwarding | Yes | Yes | Yes |
| TUN interface | Yes (native) | Loopback alias fallback | No (use SOCKS5) |
| OS routing | `ip route` | `route -n add` | No |

TUN mode on Linux creates a `holepunch0` interface via `/dev/net/tun` and requires root. On macOS, it uses a loopback alias on `lo0`. On Windows and other platforms, use the SOCKS5 proxy or TCP port forwarding instead.

## Project Structure

```
HolePunch/
├── cmd/
│   ├── server/
│   │   └── main.go              # Orchestration server
│   └── client/
│       ├── main.go              # Client with interactive REPL
│       ├── tun_linux.go         # TUN device (Linux)
│       ├── tun_darwin.go        # Loopback alias (macOS)
│       └── tun_other.go         # Stub (Windows/other)
├── pkg/
│   ├── protocol/
│   │   ├── protocol.go          # Wire protocol (10 message types)
│   │   └── protocol_test.go
│   ├── holepunch/
│   │   ├── crypto.go            # Key exchange, encryption, replay protection
│   │   ├── puncher.go           # Hole punching, peer management, cryptokey routing
│   │   ├── crypto_test.go
│   │   ├── puncher_test.go
│   │   └── edge_cases_test.go
│   ├── proxy/
│   │   ├── proxy.go             # SOCKS5, port forwarding, TUN packet handling
│   │   └── proxy_test.go
│   └── config/
│       ├── config.go            # Configuration, version info, defaults
│       ├── stats.go             # Thread-safe connection statistics
│       └── config_test.go
├── Makefile
├── go.mod
└── README.md
```

## Testing

```bash
# Run all tests
go test -v ./...

# Run tests for a specific package
go test -v ./pkg/holepunch/...
go test -v ./pkg/proxy/...
go test -v ./pkg/config/...
go test -v ./pkg/protocol/...

# Static analysis
go vet ./...
```

64 tests across 4 packages covering:
- Wire protocol serialization/parsing (15 tests)
- Crypto: key generation, ECDH, encrypt/decrypt, replay protection, session expiry, concurrency (15 tests)
- Puncher: AllowedIPs, cryptokey routing, silent mode, multi-peer routing (10 tests)
- Edge cases: overlapping routes, /32 host routes, 0.0.0.0/0 default route, IPv6, broadcast addresses (11 tests)
- Proxy: packet serialization, manager lifecycle, TUN writer, stream IDs (13 tests)
- Config: defaults, stats counters, formatting, save/load, concurrency (11 tests)

Note: `go test -race` requires `CGO_ENABLED=1` on Windows.

## License

MIT
