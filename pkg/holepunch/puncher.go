package holepunch

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// PeerConnection represents an established peer-to-peer connection
type PeerConnection struct {
	PeerID    [32]byte
	Addr      *net.UDPAddr
	Encryptor *Encryptor
	LastSeen  time.Time
	mu        sync.RWMutex
}

// Puncher handles UDP hole punching operations
type Puncher struct {
	conn       *net.UDPConn
	localKeys  *KeyPair
	peers      map[[32]byte]*PeerConnection
	peersMu    sync.RWMutex
	onData     func(peerID [32]byte, data []byte)
	onPeerConn func(peerID [32]byte)
}

// NewPuncher creates a new hole puncher
func NewPuncher(conn *net.UDPConn, keys *KeyPair) *Puncher {
	return &Puncher{
		conn:      conn,
		localKeys: keys,
		peers:     make(map[[32]byte]*PeerConnection),
	}
}

// SetDataHandler sets the callback for received data
func (p *Puncher) SetDataHandler(handler func(peerID [32]byte, data []byte)) {
	p.onData = handler
}

// SetPeerConnectedHandler sets the callback for new peer connections
func (p *Puncher) SetPeerConnectedHandler(handler func(peerID [32]byte)) {
	p.onPeerConn = handler
}

// InitiatePunch starts hole punching to a peer
func (p *Puncher) InitiatePunch(peerID [32]byte, peerPublicKey [32]byte, peerAddr *net.UDPAddr) error {
	// Compute shared secret
	sharedSecret, err := ComputeSharedSecret(&p.localKeys.PrivateKey, &peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}
	
	encryptor, err := NewEncryptor(sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}
	
	peer := &PeerConnection{
		PeerID:    peerID,
		Addr:      peerAddr,
		Encryptor: encryptor,
		LastSeen:  time.Now(),
	}
	
	p.peersMu.Lock()
	p.peers[peerID] = peer
	p.peersMu.Unlock()
	
	// Send punch packets (multiple for reliability)
	keyExMsg := &protocol.KeyExchangeMessage{PublicKey: p.localKeys.PublicKey}
	punchData := keyExMsg.Serialize()
	
	for i := 0; i < 5; i++ {
		_, err := p.conn.WriteToUDP(punchData, peerAddr)
		if err != nil {
			return fmt.Errorf("failed to send punch packet: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	
	return nil
}

// HandlePacket processes an incoming packet from a peer
func (p *Puncher) HandlePacket(data []byte, addr *net.UDPAddr) error {
	if len(data) < protocol.HeaderSize {
		return fmt.Errorf("packet too small")
	}
	
	header, err := protocol.ParseHeader(data)
	if err != nil {
		return err
	}
	
	payload := data[protocol.HeaderSize:]
	
	switch header.Type {
	case protocol.MsgTypeKeyExchange:
		return p.handleKeyExchange(payload, addr)
	case protocol.MsgTypeData:
		return p.handleData(payload, addr)
	case protocol.MsgTypeKeepalive:
		return p.handleKeepalive(addr)
	}
	
	return nil
}

func (p *Puncher) handleKeyExchange(data []byte, addr *net.UDPAddr) error {
	msg, err := protocol.ParseKeyExchangeMessage(data)
	if err != nil {
		return err
	}
	
	// Find peer by public key or create new entry
	p.peersMu.Lock()
	defer p.peersMu.Unlock()
	
	// Generate peer ID from public key (simplified)
	var peerID [32]byte
	copy(peerID[:], msg.PublicKey[:])
	
	peer, exists := p.peers[peerID]
	if !exists {
		sharedSecret, err := ComputeSharedSecret(&p.localKeys.PrivateKey, &msg.PublicKey)
		if err != nil {
			return err
		}
		
		encryptor, err := NewEncryptor(sharedSecret)
		if err != nil {
			return err
		}
		
		peer = &PeerConnection{
			PeerID:    peerID,
			Addr:      addr,
			Encryptor: encryptor,
			LastSeen:  time.Now(),
		}
		p.peers[peerID] = peer
		
		// Send our public key back
		keyExMsg := &protocol.KeyExchangeMessage{PublicKey: p.localKeys.PublicKey}
		p.conn.WriteToUDP(keyExMsg.Serialize(), addr)
		
		if p.onPeerConn != nil {
			go p.onPeerConn(peerID)
		}
	} else {
		peer.mu.Lock()
		peer.Addr = addr
		peer.LastSeen = time.Now()
		peer.mu.Unlock()
	}
	
	return nil
}

func (p *Puncher) handleData(data []byte, addr *net.UDPAddr) error {
	msg, err := protocol.ParseDataMessage(data)
	if err != nil {
		return err
	}
	
	// Find peer by address
	p.peersMu.RLock()
	var peer *PeerConnection
	for _, pc := range p.peers {
		if pc.Addr.IP.Equal(addr.IP) && pc.Addr.Port == addr.Port {
			peer = pc
			break
		}
	}
	p.peersMu.RUnlock()
	
	if peer == nil {
		return fmt.Errorf("unknown peer: %s", addr.String())
	}
	
	plaintext, err := peer.Encryptor.Decrypt(msg.Nonce, msg.Ciphertext)
	if err != nil {
		return err
	}
	
	peer.mu.Lock()
	peer.LastSeen = time.Now()
	peer.mu.Unlock()
	
	if p.onData != nil {
		go p.onData(peer.PeerID, plaintext)
	}
	
	return nil
}

func (p *Puncher) handleKeepalive(addr *net.UDPAddr) error {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()
	
	for _, peer := range p.peers {
		if peer.Addr.IP.Equal(addr.IP) && peer.Addr.Port == addr.Port {
			peer.mu.Lock()
			peer.LastSeen = time.Now()
			peer.mu.Unlock()
			break
		}
	}
	
	return nil
}

// SendToPeer sends encrypted data to a peer
func (p *Puncher) SendToPeer(peerID [32]byte, data []byte) error {
	p.peersMu.RLock()
	peer, exists := p.peers[peerID]
	p.peersMu.RUnlock()
	
	if !exists {
		return fmt.Errorf("peer not found")
	}
	
	nonce, ciphertext, err := peer.Encryptor.Encrypt(data)
	if err != nil {
		return err
	}
	
	msg := &protocol.DataMessage{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	
	_, err = p.conn.WriteToUDP(msg.Serialize(), peer.Addr)
	return err
}

// SendKeepalive sends keepalive to all peers
func (p *Puncher) SendKeepalive() {
	keepalive := protocol.Header{Version: 1, Type: protocol.MsgTypeKeepalive, Length: 0}
	data := keepalive.Serialize()
	
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()
	
	for _, peer := range p.peers {
		p.conn.WriteToUDP(data, peer.Addr)
	}
}

// GetPeers returns a list of connected peer IDs
func (p *Puncher) GetPeers() [][32]byte {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()
	
	var peers [][32]byte
	for id := range p.peers {
		peers = append(peers, id)
	}
	return peers
}
