package proxy

import (
	"testing"
)

func TestProxyPacketSerialize(t *testing.T) {
	p := &ProxyPacket{
		Type:     PacketTypeTCPConnect,
		StreamID: 12345,
		DstAddr:  "192.168.1.10:22",
		Payload:  []byte("test payload"),
	}

	data := p.Serialize()
	if len(data) == 0 {
		t.Fatal("Serialize returned empty data")
	}

	parsed, err := ParseProxyPacket(data)
	if err != nil {
		t.Fatalf("ParseProxyPacket failed: %v", err)
	}

	if parsed.Type != p.Type {
		t.Errorf("Type mismatch: got %d, want %d", parsed.Type, p.Type)
	}
	if parsed.StreamID != p.StreamID {
		t.Errorf("StreamID mismatch: got %d, want %d", parsed.StreamID, p.StreamID)
	}
	if parsed.DstAddr != p.DstAddr {
		t.Errorf("DstAddr mismatch: got %s, want %s", parsed.DstAddr, p.DstAddr)
	}
	if string(parsed.Payload) != string(p.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestIsProxyPacket(t *testing.T) {
	testCases := []struct {
		data   []byte
		expect bool
	}{
		{[]byte{byte(PacketTypeTCPConnect)}, true},
		{[]byte{byte(PacketTypeTCPData)}, true},
		{[]byte{byte(PacketTypeIPPacket)}, false}, // IP packets handled separately
		{[]byte{byte(PacketTypeUDPData)}, true},
		{[]byte{0}, false},   // Invalid type
		{[]byte{100}, false}, // Invalid type
		{[]byte{}, false},    // Empty
	}

	for _, tc := range testCases {
		got := IsProxyPacket(tc.data)
		if got != tc.expect {
			t.Errorf("IsProxyPacket(%v): got %v, want %v", tc.data, got, tc.expect)
		}
	}
}

func TestIsIPPacket(t *testing.T) {
	testCases := []struct {
		data   []byte
		expect bool
	}{
		{[]byte{byte(PacketTypeIPPacket)}, true},
		{[]byte{byte(PacketTypeTCPConnect)}, false},
		{[]byte{0}, false},
		{[]byte{}, false},
	}

	for _, tc := range testCases {
		got := IsIPPacket(tc.data)
		if got != tc.expect {
			t.Errorf("IsIPPacket(%v): got %v, want %v", tc.data, got, tc.expect)
		}
	}
}

func TestProxyPacketTypes(t *testing.T) {
	if PacketTypeTCPConnect < 20 || PacketTypeTCPConnect > 30 {
		t.Error("PacketTypeTCPConnect out of range")
	}
	if PacketTypeIPPacket != 30 {
		t.Errorf("PacketTypeIPPacket should be 30, got %d", PacketTypeIPPacket)
	}
}

func TestProxyPacketEmptyPayload(t *testing.T) {
	p := &ProxyPacket{
		Type:     PacketTypeTCPClose,
		StreamID: 1,
		DstAddr:  "10.0.0.1:80",
		Payload:  nil,
	}

	data := p.Serialize()
	parsed, err := ParseProxyPacket(data)
	if err != nil {
		t.Fatalf("ParseProxyPacket failed: %v", err)
	}

	if len(parsed.Payload) != 0 {
		t.Error("Payload should be empty")
	}
}

func TestProxyPacketLargePayload(t *testing.T) {
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	p := &ProxyPacket{
		Type:     PacketTypeTCPData,
		StreamID: 999,
		DstAddr:  "172.16.0.1:443",
		Payload:  payload,
	}

	data := p.Serialize()
	parsed, err := ParseProxyPacket(data)
	if err != nil {
		t.Fatalf("ParseProxyPacket failed: %v", err)
	}

	if len(parsed.Payload) != len(payload) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(parsed.Payload), len(payload))
	}

	for i := range payload {
		if parsed.Payload[i] != payload[i] {
			t.Errorf("Payload byte %d mismatch", i)
			break
		}
	}
}

func TestManagerCreation(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error {
		return nil
	}

	m := NewManager(sendFunc)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if len(m.streams) != 0 {
		t.Error("Should have no streams")
	}
	if len(m.listeners) != 0 {
		t.Error("Should have no listeners")
	}
	if len(m.tunConns) != 0 {
		t.Error("Should have no TUN connections")
	}
}

func TestSetTUNWriter(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error {
		return nil
	}

	m := NewManager(sendFunc)

	if m.tunWriter != nil {
		t.Error("tunWriter should be nil initially")
	}

	called := false
	m.SetTUNWriter(func(data []byte) {
		called = true
	})

	if m.tunWriter == nil {
		t.Error("tunWriter should be set")
	}

	m.tunWriter([]byte("test"))
	if !called {
		t.Error("tunWriter was not called")
	}
}

func TestIPPacketParsing(t *testing.T) {
	ipPacket := make([]byte, 40)
	ipPacket[0] = 0x45 // Version 4, IHL 5
	ipPacket[9] = 6    // Protocol TCP
	ipPacket[12] = 10
	ipPacket[13] = 0
	ipPacket[14] = 0
	ipPacket[15] = 1
	ipPacket[16] = 192
	ipPacket[17] = 168
	ipPacket[18] = 1
	ipPacket[19] = 10

	version := ipPacket[0] >> 4
	if version != 4 {
		t.Errorf("Expected IPv4 (4), got %d", version)
	}

	protocol := ipPacket[9]
	if protocol != 6 {
		t.Errorf("Expected TCP (6), got %d", protocol)
	}
}

func TestParseProxyPacketTooShort(t *testing.T) {
	_, err := ParseProxyPacket([]byte{0x14})
	if err == nil {
		t.Error("expected error for short packet")
	}
}

func TestNextStreamID(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error { return nil }
	m := NewManager(sendFunc)

	id1 := m.nextStreamID()
	id2 := m.nextStreamID()
	id3 := m.nextStreamID()

	if id1 != 1 || id2 != 2 || id3 != 3 {
		t.Errorf("stream IDs should be sequential: got %d, %d, %d", id1, id2, id3)
	}
}

func TestGetSOCKS5PortNotRunning(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error { return nil }
	m := NewManager(sendFunc)

	if m.GetSOCKS5Port() != 0 {
		t.Error("SOCKS5 port should be 0 when not running")
	}
}

func TestManagerClose(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error { return nil }
	m := NewManager(sendFunc)

	// Close should not panic on empty manager
	m.Close()

	if len(m.streams) != 0 {
		t.Error("streams should be empty after close")
	}
	if len(m.listeners) != 0 {
		t.Error("listeners should be empty after close")
	}
	if len(m.tunConns) != 0 {
		t.Error("tunConns should be empty after close")
	}
}
