package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

type Error string

const ()

func GenerateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func NewGCM(key []byte) (cipher.AEAD, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func Sign(content []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(content)
	hexHash := make([]byte, hex.EncodedLen(mac.Size()))
	hex.Encode(hexHash, mac.Sum(nil))
	return hexHash
}

func GenerateRSAKeysPem(length int) (private []byte, public []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, nil, err
	}

	//Encode private key
	privPkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	private = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privPkcs8,
		},
	)

	// Encode public key.
	pubPkcsx, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, err
	}
	public = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubPkcsx,
		},
	)
	if err != nil {
		return nil, nil, err
	}
	return private, public, nil
}

func ParsePublicKey(key []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParsePrivateKey(key []byte) (any, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}
