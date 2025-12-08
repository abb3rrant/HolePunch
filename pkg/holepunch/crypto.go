// Package holepunch provides UDP hole punching functionality
package holepunch

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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

// Encryptor handles encryption/decryption for a peer connection
type Encryptor struct {
	cipher cipher.AEAD
}

// NewEncryptor creates a new encryptor from a shared secret
func NewEncryptor(sharedSecret [32]byte) (*Encryptor, error) {
	cipher, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	return &Encryptor{cipher: cipher}, nil
}

// Encrypt encrypts plaintext and returns nonce + ciphertext
func (e *Encryptor) Encrypt(plaintext []byte) (nonce [24]byte, ciphertext []byte, err error) {
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nonce, nil, err
	}
	
	ciphertext = e.cipher.Seal(nil, nonce[:], plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext using the provided nonce
func (e *Encryptor) Decrypt(nonce [24]byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := e.cipher.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: " + err.Error())
	}
	return plaintext, nil
}

// GenerateClientID generates a random 32-byte client ID
func GenerateClientID() ([32]byte, error) {
	var id [32]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	return id, nil
}
