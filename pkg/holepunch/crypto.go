// Package holepunch provides UDP hole punching functionality
package holepunch

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// RekeyAfterTime is how long before a session signals it needs rekeying
	RekeyAfterTime = 120 * time.Second
	// RejectAfterTime is the hard cutoff after which a session is expired
	RejectAfterTime = 180 * time.Second
	// KeepaliveTimeout is the default peer keepalive timeout
	KeepaliveTimeout = 25 * time.Second
	// ReplayWindowSize is the number of sequence numbers tracked for replay protection
	ReplayWindowSize = 2048
)

// KeyPair holds a public/private key pair for X25519
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, err
	}

	// Clamp the private key per X25519 spec
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)
	return kp, nil
}

// ComputeSharedSecret computes the shared secret using X25519
func ComputeSharedSecret(privateKey, peerPublicKey *[32]byte) ([32]byte, error) {
	var sharedSecret [32]byte
	out, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return sharedSecret, err
	}
	copy(sharedSecret[:], out)
	return sharedSecret, nil
}

// ReplayWindow implements a sliding window for replay attack detection.
// It tracks which sequence numbers have been seen using a bitmap.
type ReplayWindow struct {
	lastSeq uint64
	bitmap  [ReplayWindowSize / 64]uint64
	mu      sync.Mutex
}

// NewReplayWindow creates a new replay window
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Check returns true if the sequence number is valid (not replayed, not too old).
// A valid sequence number is recorded so it will be rejected on future calls.
func (rw *ReplayWindow) Check(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq == 0 {
		return false
	}

	if seq > rw.lastSeq {
		// New highest sequence — shift the window forward
		diff := seq - rw.lastSeq
		if diff >= ReplayWindowSize {
			// Everything in the old window is now too old; clear it
			for i := range rw.bitmap {
				rw.bitmap[i] = 0
			}
		} else {
			// Shift bits forward by diff positions
			for shift := uint64(0); shift < diff; shift++ {
				idx := (rw.lastSeq + 1 + shift) % ReplayWindowSize
				rw.bitmap[idx/64] &^= 1 << (idx % 64)
			}
		}
		rw.lastSeq = seq
		// Mark this sequence as seen
		idx := seq % ReplayWindowSize
		rw.bitmap[idx/64] |= 1 << (idx % 64)
		return true
	}

	// seq <= lastSeq — check if it's within the window
	diff := rw.lastSeq - seq
	if diff >= ReplayWindowSize {
		// Too old
		return false
	}

	idx := seq % ReplayWindowSize
	bit := uint64(1) << (idx % 64)
	if rw.bitmap[idx/64]&bit != 0 {
		// Already seen (replay)
		return false
	}

	// Mark as seen
	rw.bitmap[idx/64] |= bit
	return true
}

// Encryptor handles encryption/decryption for a peer connection
type Encryptor struct {
	cipher      cipher.AEAD
	sendCounter uint64
	recvWindow  *ReplayWindow
	createdAt   time.Time
	mu          sync.Mutex
}

// NewEncryptor creates a new encryptor from a shared secret
func NewEncryptor(sharedSecret [32]byte) (*Encryptor, error) {
	c, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	return &Encryptor{
		cipher:     c,
		recvWindow: NewReplayWindow(),
		createdAt:  time.Now(),
	}, nil
}

// Encrypt encrypts plaintext and returns nonce + ciphertext.
// The nonce uses a counter in the first 8 bytes for replay protection,
// with random bytes filling the remaining 16 bytes.
func (e *Encryptor) Encrypt(plaintext []byte) (nonce [24]byte, ciphertext []byte, err error) {
	e.mu.Lock()
	e.sendCounter++
	counter := e.sendCounter
	e.mu.Unlock()

	// First 8 bytes: monotonic counter (for replay detection)
	binary.LittleEndian.PutUint64(nonce[:8], counter)
	// Remaining 16 bytes: random (prevents cross-session nonce reuse)
	if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
		return nonce, nil, err
	}

	ciphertext = e.cipher.Seal(nil, nonce[:], plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext using the provided nonce and checks for replay attacks.
func (e *Encryptor) Decrypt(nonce [24]byte, ciphertext []byte) ([]byte, error) {
	// Extract counter from nonce for replay detection
	counter := binary.LittleEndian.Uint64(nonce[:8])
	if !e.recvWindow.Check(counter) {
		return nil, errors.New("replay attack detected")
	}

	plaintext, err := e.cipher.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: " + err.Error())
	}
	return plaintext, nil
}

// NeedsRekey returns true if this session should be rekeyed
func (e *Encryptor) NeedsRekey() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Since(e.createdAt) > RekeyAfterTime
}

// IsExpired returns true if this session has exceeded its maximum lifetime
func (e *Encryptor) IsExpired() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Since(e.createdAt) > RejectAfterTime
}

// GenerateClientID generates a random 32-byte client ID
func GenerateClientID() ([32]byte, error) {
	var id [32]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	return id, nil
}
