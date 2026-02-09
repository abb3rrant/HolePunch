package holepunch

import (
	"net"
	"testing"
)

func TestEdgeCase_RouteToAgentOwnIP(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	// Peer claims 10.0.0.0/24, and agent's own IP (10.0.0.1) is in that range
	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *cidr)

	// The agent's own IP would still match the route
	foundID, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 1))
	if !found {
		t.Fatal("expected to find route for 10.0.0.1")
	}
	if foundID != peerID {
		t.Error("routed to wrong peer")
	}
}

func TestEdgeCase_OverlappingRoutes(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	// Add both a /8 and a /24 that overlap
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/8")
	_, cidr2, _ := net.ParseCIDR("10.0.1.0/24")
	p.AddAllowedIP(peerID, *cidr1)
	p.AddAllowedIP(peerID, *cidr2)

	// Both ranges should match for an IP in the /24
	foundID, found := p.LookupPeerByIP(net.IPv4(10, 0, 1, 50))
	if !found {
		t.Fatal("expected to find route for 10.0.1.50")
	}
	if foundID != peerID {
		t.Error("routed to wrong peer")
	}

	// An IP only in the /8 should also match
	foundID, found = p.LookupPeerByIP(net.IPv4(10, 1, 0, 1))
	if !found {
		t.Fatal("expected to find route for 10.1.0.1")
	}
	if foundID != peerID {
		t.Error("routed to wrong peer")
	}
}

func TestEdgeCase_NoRouteNoSession(t *testing.T) {
	p, _ := newTestPuncher(t)

	// No peers at all
	_, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 1))
	if found {
		t.Error("should not find route when no peers exist")
	}
}

func TestEdgeCase_IPv6Ignored(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	// Only IPv4 route
	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *cidr)

	// IPv6 address should not match an IPv4 route
	_, found := p.LookupPeerByIP(net.ParseIP("::1"))
	if found {
		t.Error("IPv6 address should not match IPv4 route")
	}
}

func TestEdgeCase_BroadcastAddress(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *cidr)

	// .255 (broadcast) and .0 (network) are within the CIDR
	_, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 255))
	if !found {
		t.Error("10.0.0.255 should be within 10.0.0.0/24")
	}

	_, found = p.LookupPeerByIP(net.IPv4(10, 0, 0, 0))
	if !found {
		t.Error("10.0.0.0 should be within 10.0.0.0/24")
	}
}

func TestEdgeCase_SingleHostRoute(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	// /32 — single host
	_, cidr, _ := net.ParseCIDR("10.0.0.42/32")
	p.AddAllowedIP(peerID, *cidr)

	_, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 42))
	if !found {
		t.Error("10.0.0.42 should match 10.0.0.42/32")
	}

	_, found = p.LookupPeerByIP(net.IPv4(10, 0, 0, 43))
	if found {
		t.Error("10.0.0.43 should NOT match 10.0.0.42/32")
	}

	_, found = p.LookupPeerByIP(net.IPv4(10, 0, 0, 41))
	if found {
		t.Error("10.0.0.41 should NOT match 10.0.0.42/32")
	}
}

func TestEdgeCase_DefaultRoute(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	// 0.0.0.0/0 — default route, matches everything
	_, cidr, _ := net.ParseCIDR("0.0.0.0/0")
	p.AddAllowedIP(peerID, *cidr)

	tests := []string{
		"10.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"255.255.255.255",
		"1.1.1.1",
	}

	for _, ip := range tests {
		_, found := p.LookupPeerByIP(net.ParseIP(ip))
		if !found {
			t.Errorf("%s should match 0.0.0.0/0", ip)
		}
	}
}

func TestEdgeCase_MultiplePeersSameSubnet(t *testing.T) {
	p, keys := newTestPuncher(t)

	// Two peers claiming the same subnet
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
	_, cidr2, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peer2ID, *cidr2)

	// At least one should be found (map iteration order is non-deterministic)
	foundID, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 50))
	if !found {
		t.Fatal("expected to find at least one peer for 10.0.0.50")
	}

	// The found peer should be one of the two
	if foundID != peer1ID && foundID != peer2ID {
		t.Error("found unexpected peer")
	}
}

func TestEdgeCase_LookupAfterAllRoutesRemoved(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *cidr)

	// Should be routable
	_, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 50))
	if !found {
		t.Fatal("expected route to exist")
	}

	// Remove the route
	p.RemoveAllowedIP(peerID, *cidr)

	// Should no longer be routable
	_, found = p.LookupPeerByIP(net.IPv4(10, 0, 0, 50))
	if found {
		t.Error("route should not exist after removal")
	}
}

func TestEdgeCase_IPv6CIDRRoute(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	_, cidr, _ := net.ParseCIDR("fd00::/64")
	p.AddAllowedIP(peerID, *cidr)

	// IPv6 address in the range should match
	_, found := p.LookupPeerByIP(net.ParseIP("fd00::1"))
	if !found {
		t.Error("fd00::1 should match fd00::/64")
	}

	// IPv6 outside the range should not match
	_, found = p.LookupPeerByIP(net.ParseIP("fd01::1"))
	if found {
		t.Error("fd01::1 should NOT match fd00::/64")
	}
}

func TestEdgeCase_EmptyAllowedIPs(t *testing.T) {
	p, keys := newTestPuncher(t)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	addTestPeer(p, peerID, peerKeys.PublicKey, addr, keys)

	// Peer exists but has no AllowedIPs
	ips := p.GetPeerAllowedIPs(peerID)
	if len(ips) != 0 {
		t.Errorf("expected 0 allowed IPs, got %d", len(ips))
	}

	// Nothing should route to this peer
	_, found := p.LookupPeerByIP(net.IPv4(10, 0, 0, 1))
	if found {
		t.Error("should not find route when peer has no AllowedIPs")
	}
}
