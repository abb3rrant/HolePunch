package protocol

import (
	"net"
	"testing"
)

func TestHeaderSerializeParse(t *testing.T) {
	h := &Header{Version: 1, Type: MsgTypeRegister, Length: 64}
	data := h.Serialize()

	if len(data) != HeaderSize {
		t.Fatalf("expected header size %d, got %d", HeaderSize, len(data))
	}

	parsed, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}

	if parsed.Version != h.Version {
		t.Errorf("version mismatch: want %d, got %d", h.Version, parsed.Version)
	}
	if parsed.Type != h.Type {
		t.Errorf("type mismatch: want %d, got %d", h.Type, parsed.Type)
	}
	if parsed.Length != h.Length {
		t.Errorf("length mismatch: want %d, got %d", h.Length, parsed.Length)
	}
}

func TestHeaderParseTooShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestRegisterMessageSerializeParse(t *testing.T) {
	msg := &RegisterMessage{}
	for i := range msg.ClientID {
		msg.ClientID[i] = byte(i)
	}
	for i := range msg.PublicKey {
		msg.PublicKey[i] = byte(i + 100)
	}

	data := msg.Serialize()

	// Verify header
	header, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}
	if header.Type != MsgTypeRegister {
		t.Errorf("expected type %d, got %d", MsgTypeRegister, header.Type)
	}
	if header.Length != 64 {
		t.Errorf("expected length 64, got %d", header.Length)
	}

	// Parse payload
	parsed, err := ParseRegisterMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse register message: %v", err)
	}

	if parsed.ClientID != msg.ClientID {
		t.Error("ClientID mismatch")
	}
	if parsed.PublicKey != msg.PublicKey {
		t.Error("PublicKey mismatch")
	}
}

func TestRegisterMessageParseTooShort(t *testing.T) {
	_, err := ParseRegisterMessage(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for short register message")
	}
}

func TestPunchInitMessageIPv4(t *testing.T) {
	msg := &PunchInitMessage{
		PeerAddr: &net.UDPAddr{
			IP:   net.IPv4(192, 168, 1, 100),
			Port: 12345,
		},
	}
	for i := range msg.PeerID {
		msg.PeerID[i] = byte(i)
	}
	for i := range msg.PeerPublicKey {
		msg.PeerPublicKey[i] = byte(i + 50)
	}

	data := msg.Serialize()
	parsed, err := ParsePunchInitMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse punch init: %v", err)
	}

	if parsed.PeerID != msg.PeerID {
		t.Error("PeerID mismatch")
	}
	if parsed.PeerPublicKey != msg.PeerPublicKey {
		t.Error("PeerPublicKey mismatch")
	}
	if parsed.PeerAddr.Port != 12345 {
		t.Errorf("port mismatch: want 12345, got %d", parsed.PeerAddr.Port)
	}
	if !parsed.PeerAddr.IP.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("IP mismatch: want 192.168.1.100, got %s", parsed.PeerAddr.IP)
	}
}

func TestPunchInitMessageIPv6(t *testing.T) {
	msg := &PunchInitMessage{
		PeerAddr: &net.UDPAddr{
			IP:   net.ParseIP("::1"),
			Port: 54321,
		},
	}

	data := msg.Serialize()
	parsed, err := ParsePunchInitMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse punch init IPv6: %v", err)
	}

	if parsed.PeerAddr.Port != 54321 {
		t.Errorf("port mismatch: want 54321, got %d", parsed.PeerAddr.Port)
	}
	if !parsed.PeerAddr.IP.Equal(net.ParseIP("::1")) {
		t.Errorf("IP mismatch: want ::1, got %s", parsed.PeerAddr.IP)
	}
}

func TestPunchInitParseTooShort(t *testing.T) {
	_, err := ParsePunchInitMessage(make([]byte, 50))
	if err == nil {
		t.Fatal("expected error for short punch init")
	}
}

func TestDataMessageSerializeParse(t *testing.T) {
	msg := &DataMessage{
		Ciphertext: []byte("hello encrypted world"),
	}
	for i := range msg.Nonce {
		msg.Nonce[i] = byte(i)
	}

	data := msg.Serialize()

	// Verify header
	header, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}
	if header.Type != MsgTypeData {
		t.Errorf("expected type %d, got %d", MsgTypeData, header.Type)
	}

	parsed, err := ParseDataMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse data message: %v", err)
	}

	if parsed.Nonce != msg.Nonce {
		t.Error("nonce mismatch")
	}
	if string(parsed.Ciphertext) != string(msg.Ciphertext) {
		t.Error("ciphertext mismatch")
	}
}

func TestDataMessageParseTooShort(t *testing.T) {
	_, err := ParseDataMessage(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short data message")
	}
}

func TestKeyExchangeMessageSerializeParse(t *testing.T) {
	msg := &KeyExchangeMessage{}
	for i := range msg.PublicKey {
		msg.PublicKey[i] = byte(i + 200)
	}

	data := msg.Serialize()

	header, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}
	if header.Type != MsgTypeKeyExchange {
		t.Errorf("expected type %d, got %d", MsgTypeKeyExchange, header.Type)
	}

	parsed, err := ParseKeyExchangeMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse key exchange: %v", err)
	}

	if parsed.PublicKey != msg.PublicKey {
		t.Error("public key mismatch")
	}
}

func TestKeyExchangeParseTooShort(t *testing.T) {
	_, err := ParseKeyExchangeMessage(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for short key exchange message")
	}
}

func TestAllMessageTypes(t *testing.T) {
	types := []struct {
		name  string
		value uint8
	}{
		{"Register", MsgTypeRegister},
		{"RegisterAck", MsgTypeRegisterAck},
		{"PeerList", MsgTypePeerList},
		{"PunchRequest", MsgTypePunchRequest},
		{"PunchInit", MsgTypePunchInit},
		{"PunchAck", MsgTypePunchAck},
		{"Data", MsgTypeData},
		{"Keepalive", MsgTypeKeepalive},
		{"KeyExchange", MsgTypeKeyExchange},
		{"Disconnect", MsgTypeDisconnect},
	}

	seen := make(map[uint8]string)
	for _, tt := range types {
		if existing, ok := seen[tt.value]; ok {
			t.Errorf("duplicate message type value %d: %s and %s", tt.value, existing, tt.name)
		}
		seen[tt.value] = tt.name
	}

	if len(types) != 10 {
		t.Errorf("expected 10 message types, got %d", len(types))
	}
}

func TestHeaderAllTypes(t *testing.T) {
	for _, msgType := range []uint8{
		MsgTypeRegister, MsgTypeRegisterAck, MsgTypePeerList,
		MsgTypePunchRequest, MsgTypePunchInit, MsgTypePunchAck,
		MsgTypeData, MsgTypeKeepalive, MsgTypeKeyExchange, MsgTypeDisconnect,
	} {
		h := &Header{Version: 1, Type: msgType, Length: 100}
		data := h.Serialize()
		parsed, err := ParseHeader(data)
		if err != nil {
			t.Fatalf("failed to parse header for type %d: %v", msgType, err)
		}
		if parsed.Type != msgType {
			t.Errorf("type mismatch: want %d, got %d", msgType, parsed.Type)
		}
	}
}

func TestDataMessageEmptyCiphertext(t *testing.T) {
	msg := &DataMessage{
		Ciphertext: []byte{},
	}
	data := msg.Serialize()
	parsed, err := ParseDataMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse data message with empty ciphertext: %v", err)
	}
	if len(parsed.Ciphertext) != 0 {
		t.Error("expected empty ciphertext")
	}
}

func TestDataMessageLargeCiphertext(t *testing.T) {
	ciphertext := make([]byte, 1400)
	for i := range ciphertext {
		ciphertext[i] = byte(i % 256)
	}

	msg := &DataMessage{
		Ciphertext: ciphertext,
	}
	data := msg.Serialize()
	parsed, err := ParseDataMessage(data[HeaderSize:])
	if err != nil {
		t.Fatalf("failed to parse large data message: %v", err)
	}
	if len(parsed.Ciphertext) != 1400 {
		t.Errorf("ciphertext length mismatch: want 1400, got %d", len(parsed.Ciphertext))
	}
}
