// HolePunch Client
// Connects to the orchestration server and establishes P2P connections
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/holepunch"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// Client is the HolePunch client
type Client struct {
	conn       *net.UDPConn
	serverAddr *net.UDPAddr
	clientID   [32]byte
	keys       *holepunch.KeyPair
	puncher    *holepunch.Puncher
	peers      map[string]PeerEntry // hex ID -> peer info
	peersMu    sync.RWMutex
	registered bool
	shutdown   chan struct{}
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
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	clientID, err := holepunch.GenerateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	keys, err := holepunch.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	client := &Client{
		conn:       conn,
		serverAddr: server,
		clientID:   clientID,
		keys:       keys,
		peers:      make(map[string]PeerEntry),
		shutdown:   make(chan struct{}),
	}

	client.puncher = holepunch.NewPuncher(conn, keys)
	client.puncher.SetDataHandler(client.onDataReceived)
	client.puncher.SetPeerConnectedHandler(client.onPeerConnected)

	return client, nil
}

// Run starts the client
func (c *Client) Run() error {
	log.Printf("Client ID: %s", hex.EncodeToString(c.clientID[:8]))
	log.Printf("Local address: %s", c.conn.LocalAddr().String())
	log.Printf("Connecting to server: %s", c.serverAddr.String())

	// Register with server
	if err := c.register(); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	// Start packet handler
	go c.receiveLoop()

	// Start keepalive
	go c.keepaliveLoop()

	// Interactive CLI
	go c.interactiveMode()

	// Wait for shutdown
	<-c.shutdown
	return nil
}

func (c *Client) register() error {
	msg := &protocol.RegisterMessage{
		ClientID:  c.clientID,
		PublicKey: c.keys.PublicKey,
	}

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
			log.Printf("Read error: %v", err)
			continue
		}

		// Check if from server
		if addr.IP.Equal(c.serverAddr.IP) && addr.Port == c.serverAddr.Port {
			c.handleServerPacket(buf[:n])
		} else {
			// From peer
			if err := c.puncher.HandlePacket(buf[:n], addr); err != nil {
				log.Printf("Error handling peer packet: %v", err)
			}
		}
	}
}

func (c *Client) handleServerPacket(data []byte) {
	if len(data) < protocol.HeaderSize {
		return
	}

	header, err := protocol.ParseHeader(data)
	if err != nil {
		log.Printf("Failed to parse header: %v", err)
		return
	}

	payload := data[protocol.HeaderSize:]

	switch header.Type {
	case protocol.MsgTypeRegisterAck:
		c.registered = true
		log.Println("Registered with server successfully")

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

		var peer PeerEntry
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
			log.Printf("New peer discovered: %s at %s", hexID, peer.Addr.String())
		}
	}
}

func (c *Client) handlePunchInit(data []byte) {
	msg, err := protocol.ParsePunchInitMessage(data)
	if err != nil {
		log.Printf("Failed to parse punch init: %v", err)
		return
	}

	hexID := hex.EncodeToString(msg.PeerID[:8])
	log.Printf("Initiating hole punch to peer %s at %s", hexID, msg.PeerAddr.String())

	if err := c.puncher.InitiatePunch(msg.PeerID, msg.PeerPublicKey, msg.PeerAddr); err != nil {
		log.Printf("Failed to initiate punch: %v", err)
	}

	c.peersMu.Lock()
	peer := c.peers[hexID]
	peer.Connected = true
	c.peers[hexID] = peer
	c.peersMu.Unlock()
}

func (c *Client) onDataReceived(peerID [32]byte, data []byte) {
	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("[%s]: %s", hexID, string(data))
}

func (c *Client) onPeerConnected(peerID [32]byte) {
	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("Peer connected: %s", hexID)

	c.peersMu.Lock()
	if peer, exists := c.peers[hexID]; exists {
		peer.Connected = true
		c.peers[hexID] = peer
	}
	c.peersMu.Unlock()
}

func (c *Client) keepaliveLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	keepalive := protocol.Header{Version: 1, Type: protocol.MsgTypeKeepalive, Length: 0}
	keepaliveData := keepalive.Serialize()

	for {
		select {
		case <-c.shutdown:
			return
		case <-ticker.C:
			// Send to server
			c.conn.WriteToUDP(keepaliveData, c.serverAddr)
			// Send to peers
			c.puncher.SendKeepalive()
		}
	}
}

func (c *Client) interactiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("\nHolePunch Client Interactive Mode")
	fmt.Println("Commands:")
	fmt.Println("  peers           - List discovered peers")
	fmt.Println("  connect <id>    - Connect to peer by ID prefix")
	fmt.Println("  send <id> <msg> - Send message to connected peer")
	fmt.Println("  quit            - Exit")
	fmt.Println()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		cmd := parts[0]

		switch cmd {
		case "peers":
			c.listPeers()

		case "connect":
			if len(parts) < 2 {
				fmt.Println("Usage: connect <peer-id-prefix>")
				continue
			}
			c.connectToPeer(parts[1])

		case "send":
			if len(parts) < 3 {
				fmt.Println("Usage: send <peer-id-prefix> <message>")
				continue
			}
			c.sendMessage(parts[1], parts[2])

		case "quit", "exit":
			c.shutdown <- struct{}{}
			return

		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}

func (c *Client) listPeers() {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()

	if len(c.peers) == 0 {
		fmt.Println("No peers discovered")
		return
	}

	fmt.Println("Discovered peers:")
	for hexID, peer := range c.peers {
		status := "disconnected"
		if peer.Connected {
			status = "connected"
		}
		fmt.Printf("  %s (%s) - %s\n", hexID, peer.Addr.String(), status)
	}
}

func (c *Client) connectToPeer(idPrefix string) {
	c.peersMu.RLock()
	var target *PeerEntry
	for hexID, peer := range c.peers {
		if strings.HasPrefix(hexID, idPrefix) {
			p := peer
			target = &p
			break
		}
	}
	c.peersMu.RUnlock()

	if target == nil {
		fmt.Printf("No peer found with ID prefix: %s\n", idPrefix)
		return
	}

	// Send punch request to server
	header := protocol.Header{Version: 1, Type: protocol.MsgTypePunchRequest, Length: 32}
	msg := header.Serialize()
	msg = append(msg, target.ID[:]...)

	c.conn.WriteToUDP(msg, c.serverAddr)
	fmt.Printf("Punch request sent for peer %s\n", hex.EncodeToString(target.ID[:8]))
}

func (c *Client) sendMessage(idPrefix, message string) {
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

// Shutdown gracefully shuts down the client
func (c *Client) Shutdown() {
	// Send disconnect to server
	header := protocol.Header{Version: 1, Type: protocol.MsgTypeDisconnect, Length: 0}
	c.conn.WriteToUDP(header.Serialize(), c.serverAddr)

	close(c.shutdown)
	c.conn.Close()
}

func main() {
	serverAddr := flag.String("server", "localhost:41234", "Orchestration server address")
	ipv6 := flag.Bool("6", false, "Use IPv6 instead of IPv4")
	flag.Parse()

	client, err := NewClient(*serverAddr, *ipv6)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		client.Shutdown()
	}()

	if err := client.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
