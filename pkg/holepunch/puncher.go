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
	PeerID     [32]byte
	PublicKey  [32]byte
	Addr       *net.UDPAddr
	Encryptor  *Encryptor
	AllowedIPs []net.IPNet
	LastSeen   time.Time
	mu         sync.RWMutex
}

// Puncher handles UDP hole punching operations
type Puncher struct {
	conn         *net.UDPConn
	localKeys    *KeyPair
	peers        map[[32]byte]*PeerConnection
	pubKeyToPeer map[[32]byte][32]byte // PublicKey -> PeerID
	addrToPeer   map[string][32]byte   // "IP:Port" -> PeerID
	ipToPeer     map[string][32]byte   // CIDR string -> PeerID
	peersMu      sync.RWMutex
	silentMode   bool
	onData       func(peerID [32]byte, data []byte)
	onPeerConn   func(peerID [32]byte)
}

// NewPuncher creates a new hole puncher
func NewPuncher(conn *net.UDPConn, keys *KeyPair) *Puncher {
	return &Puncher{
		conn:         conn,
		localKeys:    keys,
		peers:        make(map[[32]byte]*PeerConnection),
		pubKeyToPeer: make(map[[32]byte][32]byte),
		addrToPeer:   make(map[string][32]byte),
		ipToPeer:     make(map[string][32]byte),
		silentMode:   true,
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

// SetSilentMode enables or disables silent mode.
// In silent mode, packets from unknown peers are silently dropped.
func (p *Puncher) SetSilentMode(enabled bool) {
	p.peersMu.Lock()
	p.silentMode = enabled
	p.peersMu.Unlock()
}

// InitiatePunch starts hole punching to a peer
func (p *Puncher) InitiatePunch(peerID [32]byte, peerPublicKey [32]byte, peerAddr *net.UDPAddr) error {
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
		PublicKey: peerPublicKey,
		Addr:      peerAddr,
		Encryptor: encryptor,
		LastSeen:  time.Now(),
	}

	p.peersMu.Lock()
	p.peers[peerID] = peer
	p.pubKeyToPeer[peerPublicKey] = peerID
	p.addrToPeer[peerAddr.String()] = peerID
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

// InitiatePunchWithAllowedIPs starts hole punching and pre-registers AllowedIP routes
func (p *Puncher) InitiatePunchWithAllowedIPs(peerID [32]byte, peerPublicKey [32]byte, peerAddr *net.UDPAddr, allowedIPs []net.IPNet) error {
	if err := p.InitiatePunch(peerID, peerPublicKey, peerAddr); err != nil {
		return err
	}

	for _, ipNet := range allowedIPs {
		p.AddAllowedIP(peerID, ipNet)
	}

	return nil
}

// AddAllowedIP adds a CIDR route to a peer for cryptokey routing
func (p *Puncher) AddAllowedIP(peerID [32]byte, ipNet net.IPNet) {
	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	peer, exists := p.peers[peerID]
	if !exists {
		return
	}

	peer.mu.Lock()
	peer.AllowedIPs = append(peer.AllowedIPs, ipNet)
	peer.mu.Unlock()

	p.ipToPeer[ipNet.String()] = peerID
}

// RemoveAllowedIP removes a CIDR route from a peer
func (p *Puncher) RemoveAllowedIP(peerID [32]byte, ipNet net.IPNet) {
	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	peer, exists := p.peers[peerID]
	if !exists {
		return
	}

	peer.mu.Lock()
	for i, existing := range peer.AllowedIPs {
		if existing.String() == ipNet.String() {
			peer.AllowedIPs = append(peer.AllowedIPs[:i], peer.AllowedIPs[i+1:]...)
			break
		}
	}
	peer.mu.Unlock()

	delete(p.ipToPeer, ipNet.String())
}

// LookupPeerByIP finds which peer owns the given destination IP via AllowedIPs
func (p *Puncher) LookupPeerByIP(ip net.IP) ([32]byte, bool) {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	for _, peer := range p.peers {
		peer.mu.RLock()
		for _, ipNet := range peer.AllowedIPs {
			if ipNet.Contains(ip) {
				peer.mu.RUnlock()
				return peer.PeerID, true
			}
		}
		peer.mu.RUnlock()
	}

	var zero [32]byte
	return zero, false
}

// SendToIP encrypts and sends data to the peer that owns the destination IP
func (p *Puncher) SendToIP(ip net.IP, data []byte) error {
	peerID, found := p.LookupPeerByIP(ip)
	if !found {
		return fmt.Errorf("no route to host %s", ip.String())
	}
	return p.SendToPeer(peerID, data)
}

// GetPeerAllowedIPs returns a copy of a peer's AllowedIPs
func (p *Puncher) GetPeerAllowedIPs(peerID [32]byte) []net.IPNet {
	p.peersMu.RLock()
	peer, exists := p.peers[peerID]
	p.peersMu.RUnlock()

	if !exists {
		return nil
	}

	peer.mu.RLock()
	defer peer.mu.RUnlock()

	result := make([]net.IPNet, len(peer.AllowedIPs))
	copy(result, peer.AllowedIPs)
	return result
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

	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	// Try to find peer by public key first (most reliable identifier)
	if peerID, ok := p.pubKeyToPeer[msg.PublicKey]; ok {
		peer := p.peers[peerID]
		if peer != nil {
			peer.mu.Lock()
			oldAddr := peer.Addr.String()
			peer.Addr = addr
			peer.LastSeen = time.Now()
			peer.mu.Unlock()

			// Update address mapping if endpoint roamed
			if oldAddr != addr.String() {
				delete(p.addrToPeer, oldAddr)
				p.addrToPeer[addr.String()] = peerID
			}
			return nil
		}
	}

	// Try to find peer by address
	if peerID, ok := p.addrToPeer[addr.String()]; ok {
		peer := p.peers[peerID]
		if peer != nil {
			peer.mu.Lock()
			peer.LastSeen = time.Now()
			peer.mu.Unlock()
			return nil
		}
	}

	// Unknown peer — in silent mode, drop silently
	if p.silentMode {
		return nil
	}

	// Auto-accept: compute shared secret and create connection
	var peerID [32]byte
	copy(peerID[:], msg.PublicKey[:])

	sharedSecret, err := ComputeSharedSecret(&p.localKeys.PrivateKey, &msg.PublicKey)
	if err != nil {
		return err
	}

	encryptor, err := NewEncryptor(sharedSecret)
	if err != nil {
		return err
	}

	peer := &PeerConnection{
		PeerID:    peerID,
		PublicKey: msg.PublicKey,
		Addr:      addr,
		Encryptor: encryptor,
		LastSeen:  time.Now(),
	}
	p.peers[peerID] = peer
	p.pubKeyToPeer[msg.PublicKey] = peerID
	p.addrToPeer[addr.String()] = peerID

	// Send our public key back
	keyExMsg := &protocol.KeyExchangeMessage{PublicKey: p.localKeys.PublicKey}
	p.conn.WriteToUDP(keyExMsg.Serialize(), addr)

	if p.onPeerConn != nil {
		go p.onPeerConn(peerID)
	}

	return nil
}

func (p *Puncher) handleData(data []byte, addr *net.UDPAddr) error {
	msg, err := protocol.ParseDataMessage(data)
	if err != nil {
		return err
	}

	// O(1) peer lookup by address
	p.peersMu.RLock()
	peerID, found := p.addrToPeer[addr.String()]
	var peer *PeerConnection
	if found {
		peer = p.peers[peerID]
	}
	p.peersMu.RUnlock()

	if peer == nil {
		// If not found by address, linear scan as fallback (handles roaming)
		p.peersMu.RLock()
		for _, pc := range p.peers {
			if pc.Addr.IP.Equal(addr.IP) && pc.Addr.Port == addr.Port {
				peer = pc
				break
			}
		}
		p.peersMu.RUnlock()

		if peer == nil {
			return nil // Silently drop
		}
	}

	plaintext, err := peer.Encryptor.Decrypt(msg.Nonce, msg.Ciphertext)
	if err != nil {
		return nil // Silently drop failed decryptions (replay or tampered)
	}

	peer.mu.Lock()
	oldAddr := peer.Addr.String()
	peer.Addr = addr
	peer.LastSeen = time.Now()
	peer.mu.Unlock()

	// Update address mapping if endpoint roamed
	if oldAddr != addr.String() {
		p.peersMu.Lock()
		delete(p.addrToPeer, oldAddr)
		p.addrToPeer[addr.String()] = peer.PeerID
		p.peersMu.Unlock()
	}

	if p.onData != nil {
		go p.onData(peer.PeerID, plaintext)
	}

	return nil
}

func (p *Puncher) handleKeepalive(addr *net.UDPAddr) error {
	p.peersMu.RLock()
	peerID, found := p.addrToPeer[addr.String()]
	var peer *PeerConnection
	if found {
		peer = p.peers[peerID]
	}
	p.peersMu.RUnlock()

	if peer != nil {
		peer.mu.Lock()
		peer.LastSeen = time.Now()
		peer.mu.Unlock()
		return nil
	}

	// Fallback: linear scan
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	for _, pc := range p.peers {
		if pc.Addr.IP.Equal(addr.IP) && pc.Addr.Port == addr.Port {
			pc.mu.Lock()
			pc.LastSeen = time.Now()
			pc.mu.Unlock()
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
