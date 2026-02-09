package holepunch

import (
	"encoding/binary"
	"sync"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate second key pair: %v", err)
	}

	// Keys should be non-zero
	var zero [32]byte
	if kp1.PublicKey == zero {
		t.Error("public key is zero")
	}
	if kp1.PrivateKey == zero {
		t.Error("private key is zero")
	}

	// Two key pairs should be different
	if kp1.PublicKey == kp2.PublicKey {
		t.Error("two generated key pairs have the same public key")
	}
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two generated key pairs have the same private key")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate Alice's keys: %v", err)
	}

	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate Bob's keys: %v", err)
	}

	// Alice computes shared secret with Bob's public key
	secretA, err := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	if err != nil {
		t.Fatalf("Alice failed to compute shared secret: %v", err)
	}

	// Bob computes shared secret with Alice's public key
	secretB, err := ComputeSharedSecret(&bob.PrivateKey, &alice.PublicKey)
	if err != nil {
		t.Fatalf("Bob failed to compute shared secret: %v", err)
	}

	// Both should arrive at the same shared secret
	if secretA != secretB {
		t.Error("shared secrets don't match")
	}

	// Should not be zero
	var zero [32]byte
	if secretA == zero {
		t.Error("shared secret is zero")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)

	encAlice, err := NewEncryptor(secret)
	if err != nil {
		t.Fatalf("failed to create Alice's encryptor: %v", err)
	}

	encBob, err := NewEncryptor(secret)
	if err != nil {
		t.Fatalf("failed to create Bob's encryptor: %v", err)
	}

	plaintext := []byte("Hello, peer-to-peer world!")

	nonce, ciphertext, err := encAlice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Ciphertext should differ from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("ciphertext matches plaintext")
	}

	decrypted, err := encBob.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptLargePayload(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	encAlice, _ := NewEncryptor(secret)
	encBob, _ := NewEncryptor(secret)

	// Simulate a max-size IP packet payload
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	nonce, ciphertext, err := encAlice.Encrypt(payload)
	if err != nil {
		t.Fatalf("encryption of large payload failed: %v", err)
	}

	decrypted, err := encBob.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("decryption of large payload failed: %v", err)
	}

	if len(decrypted) != len(payload) {
		t.Fatalf("decrypted payload length mismatch: got %d, want %d", len(decrypted), len(payload))
	}

	for i := range payload {
		if decrypted[i] != payload[i] {
			t.Fatalf("payload mismatch at byte %d: got %d, want %d", i, decrypted[i], payload[i])
		}
	}
}

func TestReplayProtection(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	encAlice, _ := NewEncryptor(secret)
	encBob, _ := NewEncryptor(secret)

	plaintext := []byte("test message")

	nonce, ciphertext, err := encAlice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// First decryption should succeed
	_, err = encBob.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("first decryption failed: %v", err)
	}

	// Second decryption of the same packet should fail (replay)
	_, err = encBob.Decrypt(nonce, ciphertext)
	if err == nil {
		t.Fatal("expected replay attack to be detected")
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	encAlice, _ := NewEncryptor(secret)
	encBob, _ := NewEncryptor(secret)

	// Encrypt three messages
	nonce1, ct1, _ := encAlice.Encrypt([]byte("message 1"))
	nonce2, ct2, _ := encAlice.Encrypt([]byte("message 2"))
	nonce3, ct3, _ := encAlice.Encrypt([]byte("message 3"))

	// Receive them out of order: 3, 1, 2
	_, err := encBob.Decrypt(nonce3, ct3)
	if err != nil {
		t.Fatalf("failed to decrypt message 3: %v", err)
	}

	_, err = encBob.Decrypt(nonce1, ct1)
	if err != nil {
		t.Fatalf("failed to decrypt message 1 (out of order): %v", err)
	}

	_, err = encBob.Decrypt(nonce2, ct2)
	if err != nil {
		t.Fatalf("failed to decrypt message 2 (out of order): %v", err)
	}

	// Replay of any should fail
	_, err = encBob.Decrypt(nonce1, ct1)
	if err == nil {
		t.Fatal("replay of message 1 should have been detected")
	}

	_, err = encBob.Decrypt(nonce2, ct2)
	if err == nil {
		t.Fatal("replay of message 2 should have been detected")
	}

	_, err = encBob.Decrypt(nonce3, ct3)
	if err == nil {
		t.Fatal("replay of message 3 should have been detected")
	}
}

func TestReplayWindowSliding(t *testing.T) {
	rw := NewReplayWindow()

	// Sequence 1 should be accepted
	if !rw.Check(1) {
		t.Error("sequence 1 should be accepted")
	}

	// Sequence 2 should be accepted
	if !rw.Check(2) {
		t.Error("sequence 2 should be accepted")
	}

	// Replay of 1 should be rejected
	if rw.Check(1) {
		t.Error("replay of sequence 1 should be rejected")
	}

	// Large jump forward
	if !rw.Check(100) {
		t.Error("sequence 100 should be accepted")
	}

	// 50 is within the window and hasn't been seen
	if !rw.Check(50) {
		t.Error("sequence 50 should be accepted")
	}

	// Replay of 50
	if rw.Check(50) {
		t.Error("replay of sequence 50 should be rejected")
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	rw := NewReplayWindow()

	// Accept a high sequence number
	if !rw.Check(ReplayWindowSize + 100) {
		t.Error("high sequence should be accepted")
	}

	// Sequence 1 is now too old (outside the window)
	if rw.Check(1) {
		t.Error("sequence 1 should be too old")
	}
}

func TestReplayWindowZero(t *testing.T) {
	rw := NewReplayWindow()

	// Sequence 0 should always be rejected
	if rw.Check(0) {
		t.Error("sequence 0 should be rejected")
	}
}

func TestCounterBasedNonce(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	enc, _ := NewEncryptor(secret)

	nonce1, _, _ := enc.Encrypt([]byte("a"))
	nonce2, _, _ := enc.Encrypt([]byte("b"))
	nonce3, _, _ := enc.Encrypt([]byte("c"))

	// Extract counters from nonces
	c1 := binary.LittleEndian.Uint64(nonce1[:8])
	c2 := binary.LittleEndian.Uint64(nonce2[:8])
	c3 := binary.LittleEndian.Uint64(nonce3[:8])

	if c1 != 1 {
		t.Errorf("first counter should be 1, got %d", c1)
	}
	if c2 != 2 {
		t.Errorf("second counter should be 2, got %d", c2)
	}
	if c3 != 3 {
		t.Errorf("third counter should be 3, got %d", c3)
	}
}

func TestSessionExpiry(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	enc, _ := NewEncryptor(secret)

	// A fresh encryptor should not need rekey or be expired
	if enc.NeedsRekey() {
		t.Error("fresh session should not need rekey")
	}
	if enc.IsExpired() {
		t.Error("fresh session should not be expired")
	}
}

func TestGenerateClientID(t *testing.T) {
	id1, err := GenerateClientID()
	if err != nil {
		t.Fatalf("failed to generate client ID: %v", err)
	}

	id2, err := GenerateClientID()
	if err != nil {
		t.Fatalf("failed to generate second client ID: %v", err)
	}

	if id1 == id2 {
		t.Error("two client IDs should be different")
	}

	var zero [32]byte
	if id1 == zero {
		t.Error("client ID should not be zero")
	}
}

func TestEncryptorConcurrency(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	enc, _ := NewEncryptor(secret)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := enc.Encrypt([]byte("concurrent message"))
			if err != nil {
				t.Errorf("concurrent encryption failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	charlie, _ := GenerateKeyPair()

	secretAB, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	secretAC, _ := ComputeSharedSecret(&alice.PrivateKey, &charlie.PublicKey)

	encAB, _ := NewEncryptor(secretAB)
	encAC, _ := NewEncryptor(secretAC)

	nonce, ciphertext, _ := encAB.Encrypt([]byte("secret for Bob"))

	// Charlie should not be able to decrypt
	_, err := encAC.Decrypt(nonce, ciphertext)
	if err == nil {
		t.Fatal("decryption with wrong key should fail")
	}
}

func TestEncryptDecryptTamperedCiphertext(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	secret, _ := ComputeSharedSecret(&alice.PrivateKey, &bob.PublicKey)

	encAlice, _ := NewEncryptor(secret)
	encBob, _ := NewEncryptor(secret)

	nonce, ciphertext, _ := encAlice.Encrypt([]byte("untampered"))

	// Flip a bit in the ciphertext
	if len(ciphertext) > 0 {
		ciphertext[0] ^= 0xFF
	}

	_, err := encBob.Decrypt(nonce, ciphertext)
	if err == nil {
		t.Fatal("decryption of tampered ciphertext should fail")
	}
}
