package holepunch

import (
	"net"
	"testing"
	"time"
)

// helper to create a test puncher with a real UDP socket
func newTestPuncher(t *testing.T) (*Puncher, *KeyPair) {
	t.Helper()
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("failed to create UDP socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return NewPuncher(conn, keys), keys
}

// helper to add a peer directly for testing
func addTestPeer(p *Puncher, peerID [32]byte, pubKey [32]byte, addr *net.UDPAddr, localKeys *KeyPair) {
	secret, _ := ComputeSharedSecret(&localKeys.PrivateKey, &pubKey)
	enc, _ := NewEncryptor(secret)

	peer := &PeerConnection{
		PeerID:    peerID,
		PublicKey: pubKey,
		Addr:      addr,
		Encryptor: enc,
		LastSeen:  time.Now(),
	}

	p.peersMu.Lock()
	p.peers[peerID] = peer
	p.pubKeyToPeer[pubKey] = peerID
	p.addrToPeer[addr.String()] = peerID
	p.peersMu.Unlock()
}

func TestAddAllowedIP(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *cidr)

	allowedIPs := p.GetPeerAllowedIPs(peerID)
	if len(allowedIPs) != 1 {
		t.Fatalf("expected 1 allowed IP, got %d", len(allowedIPs))
	}
	if allowedIPs[0].String() != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %s", allowedIPs[0].String())
	}
}

func TestLookupPeerByIP(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *cidr)

	// IP within the range should match
	foundID, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 50))
	if !found {
		t.Fatal("expected to find peer for 10.0.0.50")
	}
	if foundID != peerID {
		t.Error("found wrong peer")
	}

	// IP outside the range should not match
	_, found = p.LookupPeerByIP(net.IPv4(192, 168, 1, 50))
	if found {
		t.Error("should not find peer for 192.168.1.50")
	}
}

func TestLookupPeerByIPMultipleRanges(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	cidrs := []string{"10.0.0.0/24", "172.16.0.0/16", "192.168.100.0/24"}
	for _, s := range cidrs {
		_, cidr, _ := net.ParseCIDR(s)
		p.AddAllowedIP(peerID, *cidr)
	}

	tests := []struct {
		ip    string
		found bool
	}{
		{"10.0.0.1", true},
		{"10.0.0.254", true},
		{"10.0.1.1", false},
		{"172.16.0.1", true},
		{"172.16.255.255", true},
		{"172.17.0.1", false},
		{"192.168.100.1", true},
		{"192.168.101.1", false},
	}

	for _, tt := range tests {
		_, found := p.LookupPeerByIP(net.ParseIP(tt.ip))
		if found != tt.found {
			t.Errorf("LookupPeerByIP(%s): got found=%v, want %v", tt.ip, found, tt.found)
		}
	}
}

func TestRemoveAllowedIP(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	_, cidr1, _ := net.ParseCIDR("10.0.0.0/24")
	_, cidr2, _ := net.ParseCIDR("172.16.0.0/16")
	p.AddAllowedIP(peerID, *cidr1)
	p.AddAllowedIP(peerID, *cidr2)

	if len(p.GetPeerAllowedIPs(peerID)) != 2 {
		t.Fatal("expected 2 allowed IPs")
	}

	p.RemoveAllowedIP(peerID, *cidr1)

	allowedIPs := p.GetPeerAllowedIPs(peerID)
	if len(allowedIPs) != 1 {
		t.Fatalf("expected 1 allowed IP after removal, got %d", len(allowedIPs))
	}
	if allowedIPs[0].String() != "172.16.0.0/16" {
		t.Errorf("expected 172.16.0.0/16, got %s", allowedIPs[0].String())
	}

	// The removed CIDR should no longer route
	_, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 50))
	if found {
		t.Error("10.0.0.50 should no longer route after removal")
	}
}

func TestSilentMode(t *testing.T) {
	p, _ := newTestPuncher(t)

	// Silent mode is on by default
	p.peersMu.RLock()
	if !p.silentMode {
		t.Error("silent mode should be on by default")
	}
	p.peersMu.RUnlock()

	// Toggle off
	p.SetSilentMode(false)
	p.peersMu.RLock()
	if p.silentMode {
		t.Error("silent mode should be off after SetSilentMode(false)")
	}
	p.peersMu.RUnlock()

	// Toggle on
	p.SetSilentMode(true)
	p.peersMu.RLock()
	if !p.silentMode {
		t.Error("silent mode should be on after SetSilentMode(true)")
	}
	p.peersMu.RUnlock()
}

func TestMultiplePeersRouting(t *testing.T) {
	p, keys := newTestPuncher(t)

	// Create two peers with different AllowedIPs
	peer1Keys, _ := GenerateKeyPair()
	var peer1ID [32]byte
	copy(peer1ID[:], peer1Keys.PublicKey[:])
	addTestPeer(p, peer1ID, peer1Keys.PublicKey, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000}, keys)
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peer1ID, *cidr1)

	peer2Keys, _ := GenerateKeyPair()
	var peer2ID [32]byte
	copy(peer2ID[:], peer2Keys.PublicKey[:])
	addTestPeer(p, peer2ID, peer2Keys.PublicKey, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 6000}, keys)
	_, cidr2, _ := net.ParseCIDR("192.168.0.0/16")
	p.AddAllowedIP(peer2ID, *cidr2)

	// 10.0.0.x should route to peer1
	foundID, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 42))
	if !found {
		t.Fatal("expected to find peer for 10.0.0.42")
	}
	if foundID != peer1ID {
		t.Error("10.0.0.42 should route to peer1")
	}

	// 192.168.x.x should route to peer2
	foundID, found = p.LookupPeerByIP(net.IPv4(192, 168, 1, 42))
	if !found {
		t.Fatal("expected to find peer for 192.168.1.42")
	}
	if foundID != peer2ID {
		t.Error("192.168.1.42 should route to peer2")
	}
}

func TestGetPeers(t *testing.T) {
	p, keys := newTestPuncher(t)

	// Initially empty
	peers := p.GetPeers()
	if len(peers) != 0 {
		t.Errorf("expected 0 peers initially, got %d", len(peers))
	}

	// Add one peer
	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])
	addTestPeer(p, peerID, peerKeys.PublicKey, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000}, keys)

	peers = p.GetPeers()
	if len(peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(peers))
	}
}

func TestInitiatePunchWithAllowedIPs(t *testing.T) {
	p, keys := newTestPuncher(t)
	peerKeys, _ := GenerateKeyPair()

	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	// Create a listener to absorb the punch packets
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()
	peerAddr := listener.LocalAddr().(*net.UDPAddr)

	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	allowedIPs := []net.IPNet{*cidr}

	// Disable silent mode so auto-accept works
	p.SetSilentMode(false)

	err = p.InitiatePunchWithAllowedIPs(peerID, peerKeys.PublicKey, peerAddr, allowedIPs)
	if err != nil {
		t.Fatalf("InitiatePunchWithAllowedIPs failed: %v", err)
	}

	// Verify peer was added
	peers := p.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}

	// Verify AllowedIPs were registered
	ips := p.GetPeerAllowedIPs(peerID)
	if len(ips) != 1 {
		t.Fatalf("expected 1 allowed IP, got %d", len(ips))
	}
	if ips[0].String() != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %s", ips[0].String())
	}

	// Verify IP lookup works
	foundID, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 1))
	if !found {
		t.Fatal("10.0.0.1 should be routable")
	}
	if foundID != peerID {
		t.Error("routed to wrong peer")
	}

	_ = keys // Avoid unused warning
}

func TestGetPeerAllowedIPsNonExistent(t *testing.T) {
	p, _ := newTestPuncher(t)

	var fakeID [32]byte
	ips := p.GetPeerAllowedIPs(fakeID)
	if ips != nil {
		t.Error("expected nil for non-existent peer")
	}
}

func TestAddAllowedIPNonExistentPeer(t *testing.T) {
	p, _ := newTestPuncher(t)

	var fakeID [32]byte
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	p.AddAllowedIP(fakeID, *cidr) // Should not panic
}

func TestRemoveAllowedIPNonExistentPeer(t *testing.T) {
	p, _ := newTestPuncher(t)

	var fakeID [32]byte
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	p.RemoveAllowedIP(fakeID, *cidr) // Should not panic
}
