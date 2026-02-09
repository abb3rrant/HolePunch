// HolePunch Client - UDP hole punching VPN for network pivoting
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/config"
	"github.com/abb3rrant/HolePunch/pkg/holepunch"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
	"github.com/abb3rrant/HolePunch/pkg/proxy"
)

// Client is the HolePunch client
type Client struct {
	conn         *net.UDPConn
	serverAddr   *net.UDPAddr
	clientID     [32]byte
	keys         *holepunch.KeyPair
	puncher      *holepunch.Puncher
	peers        map[string]*PeerEntry
	peersMu      sync.RWMutex
	registered   bool
	shutdown     chan struct{}
	proxyManager *proxy.Manager
	stats        *config.Stats
	startTime    time.Time

	// Tunnel state
	session       *PeerEntry
	tunnelStarted bool
	tunnelIface   string
	tunnelRoutes  []string
	tunFile       *os.File // TUN device file descriptor
}

// PeerEntry stores information about a known peer
type PeerEntry struct {
	ID        [32]byte
	PublicKey [32]byte
	Addr      *net.UDPAddr
	Connected bool
}

// NewClient creates a new HolePunch client
func NewClient(serverAddr string, useIPv6 bool) (*Client, error) {
	network := "udp4"
	if useIPv6 {
		network = "udp6"
	}

	server, err := net.ResolveUDPAddr(network, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server: %w", err)
	}

	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	clientID, err := holepunch.GenerateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	keys, err := holepunch.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	client := &Client{
		conn:       conn,
		serverAddr: server,
		clientID:   clientID,
		keys:       keys,
		peers:      make(map[string]*PeerEntry),
		shutdown:   make(chan struct{}),
		stats:      config.NewStats(),
		startTime:  time.Now(),
	}

	client.puncher = holepunch.NewPuncher(conn, keys)
	client.puncher.SetDataHandler(client.onDataReceived)
	client.puncher.SetPeerConnectedHandler(client.onPeerConnected)
	client.proxyManager = proxy.NewManager(client.puncher.SendToPeer)

	return client, nil
}

// Run starts the client
func (c *Client) Run() error {
	log.Printf("Client ID: %s", hex.EncodeToString(c.clientID[:8]))
	log.Printf("Connecting to: %s", c.serverAddr.String())

	if err := c.register(); err != nil {
		return fmt.Errorf("register failed: %w", err)
	}

	go c.receiveLoop()
	go c.keepaliveLoop()
	go c.interactiveMode()

	<-c.shutdown
	return nil
}

func (c *Client) register() error {
	msg := &protocol.RegisterMessage{ClientID: c.clientID, PublicKey: c.keys.PublicKey}
	_, err := c.conn.WriteToUDP(msg.Serialize(), c.serverAddr)
	return err
}

func (c *Client) receiveLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.shutdown:
			return
		default:
		}

		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if addr.IP.Equal(c.serverAddr.IP) && addr.Port == c.serverAddr.Port {
			c.handleServerPacket(buf[:n])
		} else {
			c.puncher.HandlePacket(buf[:n], addr)
		}
	}
}

func (c *Client) handleServerPacket(data []byte) {
	if len(data) < protocol.HeaderSize {
		return
	}

	header, err := protocol.ParseHeader(data)
	if err != nil {
		return
	}

	payload := data[protocol.HeaderSize:]

	switch header.Type {
	case protocol.MsgTypeRegisterAck:
		c.registered = true
		log.Println("Registered with server")

	case protocol.MsgTypePeerList:
		c.handlePeerList(payload)

	case protocol.MsgTypePunchInit:
		c.handlePunchInit(payload)
	}
}

func (c *Client) handlePeerList(data []byte) {
	if len(data) < 1 {
		return
	}

	count := int(data[0])
	offset := 1

	c.peersMu.Lock()
	defer c.peersMu.Unlock()

	for i := 0; i < count; i++ {
		if offset+64 > len(data) {
			break
		}

		peer := &PeerEntry{}
		copy(peer.ID[:], data[offset:offset+32])
		copy(peer.PublicKey[:], data[offset+32:offset+64])
		offset += 64

		if offset+3 > len(data) {
			break
		}

		port := binary.BigEndian.Uint16(data[offset : offset+2])
		ipLen := int(data[offset+2])
		offset += 3

		if offset+ipLen > len(data) {
			break
		}

		peer.Addr = &net.UDPAddr{
			IP:   net.IP(data[offset : offset+ipLen]),
			Port: int(port),
		}
		offset += ipLen

		hexID := hex.EncodeToString(peer.ID[:8])
		if _, exists := c.peers[hexID]; !exists {
			c.peers[hexID] = peer
			log.Printf("Agent discovered: %s at %s", hexID, peer.Addr.String())
		}
	}
}

func (c *Client) handlePunchInit(data []byte) {
	msg, err := protocol.ParsePunchInitMessage(data)
	if err != nil {
		return
	}

	hexID := hex.EncodeToString(msg.PeerID[:8])
	log.Printf("Connecting to agent %s", hexID)

	if err := c.puncher.InitiatePunch(msg.PeerID, msg.PeerPublicKey, msg.PeerAddr); err != nil {
		log.Printf("Punch failed: %v", err)
	}

	c.peersMu.Lock()
	if peer, exists := c.peers[hexID]; exists {
		peer.Connected = true
	}
	c.peersMu.Unlock()
}

func (c *Client) onDataReceived(peerID [32]byte, data []byte) {
	if len(data) == 0 {
		return
	}

	// Route proxy packets (types 20-25) and IP packets (type 30) to the proxy manager
	if proxy.IsProxyPacket(data) || proxy.IsIPPacket(data) {
		if err := c.proxyManager.HandlePacket(peerID, data); err != nil {
			log.Printf("Proxy packet error: %v", err)
		}
		return
	}

	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("[%s]: %s", hexID, string(data))
}

func (c *Client) onPeerConnected(peerID [32]byte) {
	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("Agent connected: %s", hexID)

	c.peersMu.Lock()
	if peer, exists := c.peers[hexID]; exists {
		peer.Connected = true
	}
	c.peersMu.Unlock()
}

func (c *Client) keepaliveLoop() {
	ticker := time.NewTicker(holepunch.KeepaliveTimeout)
	defer ticker.Stop()

	keepalive := protocol.Header{Version: 1, Type: protocol.MsgTypeKeepalive, Length: 0}
	keepaliveData := keepalive.Serialize()

	for {
		select {
		case <-c.shutdown:
			return
		case <-ticker.C:
			c.conn.WriteToUDP(keepaliveData, c.serverAddr)
			c.puncher.SendKeepalive()
		}
	}
}

// ============================================================================
// Interactive REPL
// ============================================================================

func (c *Client) interactiveMode() {
	scanner := bufio.NewScanner(os.Stdin)
	c.printBanner()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		args := strings.Fields(line)
		cmd := strings.ToLower(args[0])

		switch cmd {
		case "help", "?":
			c.printHelp()
		case "session":
			c.cmdSession(args[1:])
		case "tunnel":
			c.cmdTunnel(args[1:])
		case "route":
			c.cmdRoute(args[1:])
		case "ifconfig":
			c.cmdIfconfig()
		case "agents", "peers":
			c.cmdAgents()
		case "connect":
			// Legacy: connect command for backward compatibility
			if len(args) < 2 {
				fmt.Println("Usage: connect <peer-id-prefix>")
			} else {
				c.cmdSession(args[1:])
			}
		case "send":
			if len(args) < 3 {
				fmt.Println("Usage: send <peer-id-prefix> <message>")
			} else {
				c.cmdSend(args[1], strings.Join(args[2:], " "))
			}
		case "listener", "forward":
			c.cmdListener(args[1:])
		case "socks":
			c.cmdSocks(args[1:])
		case "stats":
			c.cmdStats()
		case "version":
			c.cmdVersion()
		case "quit", "exit":
			c.Shutdown()
			return
		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}

func (c *Client) printBanner() {
	fmt.Println()
	fmt.Printf("  %s\n", config.VersionInfo())
	fmt.Println("  Type 'help' for commands")
	fmt.Println()
}

func (c *Client) printHelp() {
	fmt.Print(`
Commands:
  agents                        - List connected agents
  session [id]                  - Select agent for tunneling
  send <id> <message>           - Send message to connected peer

Tunnel (Linux operator, requires sudo):
  tunnel start                  - Start TUN interface
  tunnel stop                   - Stop TUN interface
  route add <cidr>              - Route network through tunnel (AllowedIP)
  route del <cidr>              - Remove route
  route list                    - Show routes
  ifconfig                      - Show tunnel info

Listeners (no root needed):
  listener add <local>:<remote> - Forward local port to remote via agent
  listener del <port>           - Remove listener
  listener list                 - Show listeners

SOCKS (no root needed):
  socks start [port]            - Start SOCKS5 proxy (default: 1080)
  socks stop                    - Stop SOCKS5 proxy

Info:
  stats                         - Show connection statistics
  version                       - Show version info
  help                          - Show this help
  quit                          - Exit
`)
}

func (c *Client) cmdSend(idPrefix, message string) {
	c.peersMu.RLock()
	var targetID [32]byte
	found := false
	for hexID, peer := range c.peers {
		if strings.HasPrefix(hexID, idPrefix) && peer.Connected {
			targetID = peer.ID
			found = true
			break
		}
	}
	c.peersMu.RUnlock()

	if !found {
		fmt.Printf("No connected peer found with ID prefix: %s\n", idPrefix)
		return
	}

	if err := c.puncher.SendToPeer(targetID, []byte(message)); err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		return
	}
	fmt.Println("Message sent")
}

func (c *Client) cmdStats() {
	snap := c.stats.Snapshot()
	fmt.Println("Connection Statistics:")
	fmt.Printf("  Uptime:           %s\n", config.FormatDuration(snap.Uptime))
	fmt.Printf("  Idle:             %s\n", config.FormatDuration(snap.IdleTime))
	fmt.Printf("  Bytes sent:       %s\n", config.FormatBytes(snap.BytesSent))
	fmt.Printf("  Bytes received:   %s\n", config.FormatBytes(snap.BytesReceived))
	fmt.Printf("  Packets sent:     %d\n", snap.PacketsSent)
	fmt.Printf("  Packets received: %d\n", snap.PacketsReceived)
	fmt.Printf("  Active streams:   %d\n", snap.ActiveStreams)
	fmt.Printf("  Connections:      %d\n", snap.Connections)
	if snap.ReplayBlocked > 0 {
		fmt.Printf("  Replay blocked:   %d\n", snap.ReplayBlocked)
	}
	if snap.DroppedPackets > 0 {
		fmt.Printf("  Dropped packets:  %d\n", snap.DroppedPackets)
	}
}

func (c *Client) cmdVersion() {
	fmt.Println(config.VersionInfo())
	fmt.Printf("  Go version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func (c *Client) cmdAgents() {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()

	if len(c.peers) == 0 {
		fmt.Println("No agents connected")
		return
	}

	fmt.Println("\nAgents:")
	for hexID, peer := range c.peers {
		status := "waiting"
		if peer.Connected {
			status = "connected"
		}
		selected := ""
		if c.session != nil && c.session.ID == peer.ID {
			selected = " [SELECTED]"
		}
		fmt.Printf("  %s - %s (%s)%s\n", hexID, peer.Addr.String(), status, selected)
	}
	fmt.Println()
}

func (c *Client) cmdSession(args []string) {
	if len(args) == 0 {
		if c.session == nil {
			fmt.Println("No session. Use: session <agent-id>")
			return
		}
		fmt.Printf("Session: %s\n", hex.EncodeToString(c.session.ID[:8]))
		return
	}

	prefix := args[0]

	c.peersMu.RLock()
	var target *PeerEntry
	for hexID, peer := range c.peers {
		if strings.HasPrefix(hexID, prefix) {
			target = peer
			break
		}
	}
	c.peersMu.RUnlock()

	if target == nil {
		fmt.Printf("No agent: %s\n", prefix)
		return
	}

	if !target.Connected {
		header := protocol.Header{Version: 1, Type: protocol.MsgTypePunchRequest, Length: 32}
		msg := header.Serialize()
		msg = append(msg, target.ID[:]...)
		c.conn.WriteToUDP(msg, c.serverAddr)
		fmt.Println("Connecting...")
		time.Sleep(2 * time.Second)

		c.peersMu.RLock()
		target = c.peers[hex.EncodeToString(target.ID[:8])]
		c.peersMu.RUnlock()

		if target == nil || !target.Connected {
			fmt.Println("Connection failed")
			return
		}
	}

	c.session = target
	fmt.Printf("Session: %s\n", hex.EncodeToString(target.ID[:8]))
	fmt.Println("Use 'tunnel start' or 'socks start' to begin")
}

// ============================================================================
// Tunnel Commands
// ============================================================================

func (c *Client) cmdTunnel(args []string) {
	if c.session == nil {
		fmt.Println("Select session first: session <id>")
		return
	}

	if len(args) == 0 {
		if c.tunnelStarted {
			fmt.Printf("Tunnel: %s (up)\n", c.tunnelIface)
		} else {
			fmt.Println("Tunnel not started")
		}
		return
	}

	switch args[0] {
	case "start":
		c.startTunnel()
	case "stop":
		c.stopTunnel()
	default:
		fmt.Println("Usage: tunnel start|stop")
	}
}

func (c *Client) startTunnel() {
	if c.tunnelStarted {
		fmt.Println("Already started")
		return
	}

	if err := c.createTun(); err != nil {
		fmt.Printf("Failed: %v\n", err)
		return
	}

	c.tunnelStarted = true
	c.proxyManager.SetTUNWriter(c.tunWritePacket)
	go c.tunReadLoop()

	fmt.Printf("Tunnel %s is up\n", c.tunnelIface)
	fmt.Println("Add routes: route add <cidr>")
}

func (c *Client) tunReadLoop() {
	if c.tunFile == nil {
		return
	}

	buf := make([]byte, 1500)
	for c.tunnelStarted {
		n, err := c.tunFile.Read(buf)
		if err != nil {
			if c.tunnelStarted {
				log.Printf("TUN read error: %v", err)
			}
			return
		}

		if n < 20 {
			continue
		}

		ipPacket := buf[:n]
		version := ipPacket[0] >> 4
		if version != 4 {
			continue
		}

		dstIP := net.IP(ipPacket[16:20])
		peerID, found := c.puncher.LookupPeerByIP(dstIP)

		var targetPeerID [32]byte
		if found {
			targetPeerID = peerID
		} else if c.session != nil {
			targetPeerID = c.session.ID
		} else {
			continue
		}

		ipCopy := make([]byte, n)
		copy(ipCopy, ipPacket)

		if err := c.proxyManager.SendIPPacket(targetPeerID, ipCopy); err != nil {
			log.Printf("TUN: failed to send IP packet: %v", err)
		}
	}
}

func (c *Client) tunWritePacket(ipPacket []byte) {
	if c.tunFile == nil || !c.tunnelStarted {
		return
	}

	_, err := c.tunFile.Write(ipPacket)
	if err != nil {
		log.Printf("TUN write error: %v", err)
	}
}

func (c *Client) stopTunnel() {
	if !c.tunnelStarted {
		fmt.Println("Not started")
		return
	}

	c.tunnelStarted = false

	for _, route := range c.tunnelRoutes {
		c.delRoute(route)
	}
	c.tunnelRoutes = nil

	c.destroyTun()

	fmt.Println("Tunnel stopped")
}

// ============================================================================
// Route Commands
// ============================================================================

func (c *Client) cmdRoute(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: route add|del|list <cidr>")
		return
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: route add <cidr>")
			return
		}
		c.addRoute(args[1])
	case "del", "delete":
		if len(args) < 2 {
			fmt.Println("Usage: route del <cidr>")
			return
		}
		c.delRoute(args[1])
	case "list":
		c.listRoutes()
	default:
		fmt.Println("Usage: route add|del|list")
	}
}

func (c *Client) addRoute(cidr string) {
	if !c.tunnelStarted {
		fmt.Println("Start tunnel first")
		return
	}

	if c.session == nil {
		fmt.Println("No session")
		return
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Invalid CIDR: %s\n", cidr)
		return
	}

	// Add to puncher's AllowedIPs for cryptokey routing
	c.puncher.AddAllowedIP(c.session.ID, *ipnet)

	// Add OS route
	if err := c.addOSRoute(cidr); err != nil {
		fmt.Printf("Warning: OS route failed: %v\n", err)
	}

	c.tunnelRoutes = append(c.tunnelRoutes, cidr)
	fmt.Printf("Route added: %s (AllowedIP for peer)\n", cidr)
}

func (c *Client) delRoute(cidr string) {
	_, ipnet, _ := net.ParseCIDR(cidr)

	if c.session != nil && ipnet != nil {
		c.puncher.RemoveAllowedIP(c.session.ID, *ipnet)
	}

	c.delOSRoute(cidr)

	var newRoutes []string
	for _, r := range c.tunnelRoutes {
		if r != cidr {
			newRoutes = append(newRoutes, r)
		}
	}
	c.tunnelRoutes = newRoutes
	fmt.Printf("Route removed: %s\n", cidr)
}

func (c *Client) listRoutes() {
	if len(c.tunnelRoutes) == 0 {
		fmt.Println("No routes")
		return
	}
	fmt.Println("Routes (AllowedIPs):")
	for _, r := range c.tunnelRoutes {
		peerInfo := ""
		if c.session != nil {
			peerInfo = fmt.Sprintf(" -> peer %s", hex.EncodeToString(c.session.ID[:4]))
		}
		fmt.Printf("  %s%s\n", r, peerInfo)
	}
}

func (c *Client) cmdIfconfig() {
	if !c.tunnelStarted {
		fmt.Println("Tunnel not started")
		return
	}
	fmt.Println("Interface:")
	fmt.Printf("  interface: %s\n", c.tunnelIface)
	fmt.Printf("  public key: %s\n", hex.EncodeToString(c.keys.PublicKey[:8]))
	if c.session != nil {
		fmt.Printf("\nPeer: %s\n", hex.EncodeToString(c.session.ID[:8]))
		fmt.Printf("  endpoint: %s\n", c.session.Addr.String())
		allowedIPs := c.puncher.GetPeerAllowedIPs(c.session.ID)
		if len(allowedIPs) > 0 {
			fmt.Printf("  allowed ips: ")
			for i, ip := range allowedIPs {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s", ip.String())
			}
			fmt.Println()
		}
	}
}

// ============================================================================
// Listener Commands (TCP Port Forwarding)
// ============================================================================

func (c *Client) cmdListener(args []string) {
	if c.session == nil {
		fmt.Println("Select session first: session <id>")
		return
	}

	if len(args) == 0 {
		fmt.Println("Usage: listener add|del|list")
		return
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: listener add <local-port>:<remote-host:port>")
			fmt.Println("Example: listener add 8080:192.168.1.10:80")
			return
		}
		parts := strings.SplitN(args[1], ":", 2)
		if len(parts) != 2 {
			fmt.Println("Invalid format. Use: <local-port>:<remote-host:port>")
			return
		}
		localPort, err := strconv.Atoi(parts[0])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", parts[0])
			return
		}
		remoteAddr := parts[1]
		if err := c.proxyManager.AddPortForward(localPort, remoteAddr, c.session.ID); err != nil {
			fmt.Printf("Failed: %v\n", err)
			return
		}
		fmt.Printf("Listener: 127.0.0.1:%d -> %s\n", localPort, remoteAddr)

	case "del", "delete":
		if len(args) < 2 {
			fmt.Println("Usage: listener del <port>")
			return
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", args[1])
			return
		}
		c.proxyManager.RemovePortForward(port)
		fmt.Printf("Listener removed: %d\n", port)

	case "list":
		forwards := c.proxyManager.ListPortForwards()
		if len(forwards) == 0 {
			fmt.Println("No listeners")
			return
		}
		fmt.Println("Listeners:")
		for _, f := range forwards {
			fmt.Printf("  127.0.0.1:%d -> %s\n", f.LocalPort, f.RemoteAddr)
		}
	}
}

// ============================================================================
// SOCKS5 Commands
// ============================================================================

func (c *Client) cmdSocks(args []string) {
	if len(args) == 0 {
		port := c.proxyManager.GetSOCKS5Port()
		if port > 0 {
			fmt.Printf("SOCKS5: 127.0.0.1:%d\n", port)
		} else {
			fmt.Println("SOCKS5 not running")
		}
		return
	}

	switch args[0] {
	case "start":
		if c.session == nil {
			fmt.Println("Select session first: session <id>")
			return
		}
		port := 1080
		if len(args) > 1 {
			p, err := strconv.Atoi(args[1])
			if err == nil {
				port = p
			}
		}
		if err := c.proxyManager.StartSOCKS5(port, c.session.ID); err != nil {
			fmt.Printf("Failed: %v\n", err)
			return
		}
		fmt.Printf("SOCKS5 started: 127.0.0.1:%d\n", port)
		fmt.Println("Usage examples:")
		fmt.Printf("  curl --socks5 127.0.0.1:%d http://target\n", port)
		fmt.Printf("  proxychains nmap -sT target\n")

	case "stop":
		c.proxyManager.StopSOCKS5()
		fmt.Println("SOCKS5 stopped")
	}
}

// ============================================================================
// Lifecycle
// ============================================================================

// Shutdown gracefully shuts down the client
func (c *Client) Shutdown() {
	if c.tunnelStarted {
		c.stopTunnel()
	}
	if c.proxyManager != nil {
		c.proxyManager.Close()
	}
	header := protocol.Header{Version: 1, Type: protocol.MsgTypeDisconnect, Length: 0}
	c.conn.WriteToUDP(header.Serialize(), c.serverAddr)
	close(c.shutdown)
	c.conn.Close()
}

func main() {
	serverAddr := flag.String("server", "localhost:41234", "Server address")
	ipv6 := flag.Bool("6", false, "Use IPv6")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(config.VersionInfo())
		os.Exit(0)
	}

	client, err := NewClient(*serverAddr, *ipv6)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		client.Shutdown()
	}()

	if err := client.Run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
