package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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
	return mac.Sum(nil)
}

//func Hash() {}

// PKCS7 Padding
func Pad(src []byte, blockSize int) []byte {
	padding := (blockSize - len(src)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7 UnPadding
func UnPad(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	pc := input[len(input)-1]
	pl := int(pc) // Convert to integer
	err := checkPaddingIsValid(input, pl)
	if err != nil {
		return nil, err
	}
	return input[:len(input)-pl], nil
}

// Check if padding is valid
func checkPaddingIsValid(input []byte, paddingLength int) error {
	if len(input) < paddingLength {
		return errors.New("invalid")
	}
	p := input[len(input)-(paddingLength):]
	for _, pc := range p {
		if uint(pc) != uint(len(p)) {
			return errors.New("invalid")
		}
	}
	return nil
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
