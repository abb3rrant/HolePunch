// HolePunch Orchestration Server
// Coordinates UDP hole punching between clients
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// ClientInfo stores information about a connected client
type ClientInfo struct {
	ID        [32]byte
	PublicKey [32]byte
	Addr      *net.UDPAddr
	LastSeen  time.Time
}

// Server is the orchestration server
type Server struct {
	conn     *net.UDPConn
	clients  map[[32]byte]*ClientInfo
	mu       sync.RWMutex
	shutdown chan struct{}
}

// NewServer creates a new orchestration server
func NewServer(addr string) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	return &Server{
		conn:     conn,
		clients:  make(map[[32]byte]*ClientInfo),
		shutdown: make(chan struct{}),
	}, nil
}

// Run starts the server
func (s *Server) Run() error {
	log.Printf("HolePunch server listening on %s", s.conn.LocalAddr().String())

	// Start cleanup goroutine
	go s.cleanupStaleClients()

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.shutdown:
			return nil
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		go s.handlePacket(buf[:n], addr)
	}
}

func (s *Server) handlePacket(data []byte, addr *net.UDPAddr) {
	if len(data) < protocol.HeaderSize {
		log.Printf("Packet too small from %s", addr.String())
		return
	}

	header, err := protocol.ParseHeader(data)
	if err != nil {
		log.Printf("Failed to parse header: %v", err)
		return
	}

	payload := data[protocol.HeaderSize:]

	switch header.Type {
	case protocol.MsgTypeRegister:
		s.handleRegister(payload, addr)
	case protocol.MsgTypePunchRequest:
		s.handlePunchRequest(payload, addr)
	case protocol.MsgTypeKeepalive:
		s.handleKeepalive(addr)
	case protocol.MsgTypeDisconnect:
		s.handleDisconnect(payload, addr)
	default:
		log.Printf("Unknown message type %d from %s", header.Type, addr.String())
	}
}

func (s *Server) handleRegister(data []byte, addr *net.UDPAddr) {
	msg, err := protocol.ParseRegisterMessage(data)
	if err != nil {
		log.Printf("Failed to parse register message: %v", err)
		return
	}

	client := &ClientInfo{
		ID:        msg.ClientID,
		PublicKey: msg.PublicKey,
		Addr:      addr,
		LastSeen:  time.Now(),
	}

	s.mu.Lock()
	s.clients[msg.ClientID] = client
	s.mu.Unlock()

	log.Printf("Client registered: %s from %s", hex.EncodeToString(msg.ClientID[:8]), addr.String())

	// Send acknowledgment
	ack := protocol.Header{Version: 1, Type: protocol.MsgTypeRegisterAck, Length: 0}
	s.conn.WriteToUDP(ack.Serialize(), addr)

	// Send peer list to all clients
	s.broadcastPeerList()
}

func (s *Server) handlePunchRequest(data []byte, addr *net.UDPAddr) {
	if len(data) < 32 {
		log.Printf("Punch request too short from %s", addr.String())
		return
	}

	var targetID [32]byte
	copy(targetID[:], data[:32])

	// Find the requesting client
	var requester *ClientInfo
	s.mu.RLock()
	for _, c := range s.clients {
		if c.Addr.IP.Equal(addr.IP) && c.Addr.Port == addr.Port {
			requester = c
			break
		}
	}
	target := s.clients[targetID]
	s.mu.RUnlock()

	if requester == nil {
		log.Printf("Punch request from unknown client %s", addr.String())
		return
	}

	if target == nil {
		log.Printf("Punch request for unknown target %s", hex.EncodeToString(targetID[:8]))
		return
	}

	log.Printf("Punch request: %s -> %s",
		hex.EncodeToString(requester.ID[:8]),
		hex.EncodeToString(target.ID[:8]))

	// Send punch init to both clients
	// Tell requester about target
	toRequester := &protocol.PunchInitMessage{
		PeerID:        target.ID,
		PeerPublicKey: target.PublicKey,
		PeerAddr:      target.Addr,
	}
	s.conn.WriteToUDP(toRequester.Serialize(), requester.Addr)

	// Tell target about requester
	toTarget := &protocol.PunchInitMessage{
		PeerID:        requester.ID,
		PeerPublicKey: requester.PublicKey,
		PeerAddr:      requester.Addr,
	}
	s.conn.WriteToUDP(toTarget.Serialize(), target.Addr)
}

func (s *Server) handleKeepalive(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, client := range s.clients {
		if client.Addr.IP.Equal(addr.IP) && client.Addr.Port == addr.Port {
			client.LastSeen = time.Now()
			break
		}
	}
}

func (s *Server) handleDisconnect(data []byte, addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, client := range s.clients {
		if client.Addr.IP.Equal(addr.IP) && client.Addr.Port == addr.Port {
			delete(s.clients, id)
			log.Printf("Client disconnected: %s", hex.EncodeToString(id[:8]))
			break
		}
	}
}

func (s *Server) broadcastPeerList() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build peer list for each client (excluding themselves)
	for clientID, client := range s.clients {
		var peerData []byte
		peerCount := 0

		for peerID, peer := range s.clients {
			if peerID == clientID {
				continue
			}

			peerData = append(peerData, peer.ID[:]...)
			peerData = append(peerData, peer.PublicKey[:]...)

			addrBytes := peer.Addr.IP.To4()
			if addrBytes == nil {
				addrBytes = peer.Addr.IP.To16()
			}

			portBytes := make([]byte, 2)
			portBytes[0] = byte(peer.Addr.Port >> 8)
			portBytes[1] = byte(peer.Addr.Port)
			peerData = append(peerData, portBytes...)
			peerData = append(peerData, byte(len(addrBytes)))
			peerData = append(peerData, addrBytes...)

			peerCount++
		}

		if peerCount > 0 {
			header := protocol.Header{
				Version: 1,
				Type:    protocol.MsgTypePeerList,
				Length:  uint16(1 + len(peerData)),
			}
			msg := header.Serialize()
			msg = append(msg, byte(peerCount))
			msg = append(msg, peerData...)

			s.conn.WriteToUDP(msg, client.Addr)
		}
	}
}

func (s *Server) cleanupStaleClients() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.mu.Lock()
			for id, client := range s.clients {
				if time.Since(client.LastSeen) > 2*time.Minute {
					delete(s.clients, id)
					log.Printf("Client timed out: %s", hex.EncodeToString(id[:8]))
				}
			}
			s.mu.Unlock()
		}
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() {
	close(s.shutdown)
	s.conn.Close()
}

func main() {
	port := flag.Int("port", 41234, "UDP port to listen on")
	bind := flag.String("bind", "0.0.0.0", "Address to bind to")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	server, err := NewServer(addr)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Println("Starting HolePunch orchestration server...")
	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
