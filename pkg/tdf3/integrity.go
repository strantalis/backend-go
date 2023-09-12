package tdf3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
)

const segmentSize int = 1024 * 1024

type IntegrityInformation struct {
	EncryptedSegmentSizeDefault int       `json:"encryptedSegmentSizeDefault"`
	RootSignature               Signature `json:"rootSignature"`
	SegmentHashAlg              string    `json:"segmentHashAlg"`
	SegmentSizeDefault          int       `json:"segmentSizeDefault"`
	Segments                    []Segment `json:"segments"`
}

type Segment struct {
	EncryptedSegmentSize int    `json:"encryptedSegmentSize"`
	Hash                 []byte `json:"hash"`
	SegmentSize          int    `json:"segmentSize,omitempty"`
}

type Signature struct {
	Alg string `json:"alg"`
	Sig []byte `json:"sig"`
}

// What do we actually use to generate the root signature
func (i *IntegrityInformation) GetRootSignature(key []byte) (Signature, error) {
	var rootSignature Signature
	rootSignature.Alg = "HS256"

	var toSign []byte
	for _, segment := range i.Segments {
		// Combine all segments to be signed
		toSign = append(toSign, segment.Hash...)
	}

	rootSignature.Sig = tdfCrypto.Sign(toSign, key)

	return rootSignature, nil
}

func (s *Segment) Build(content []byte, key []byte) {
	s.SegmentSize = segmentSize
	s.EncryptedSegmentSize = len(content)
	s.Hash = tdfCrypto.Sign(content, key)
}

func (i *IntegrityInformation) Validate(key []byte) error {
	sig, err := i.GetRootSignature(key)
	if err != nil {
		return errors.Join(errors.New("error validating root signature"), err)
	}
	if !bytes.Equal(sig.Sig, i.RootSignature.Sig) {
		return fmt.Errorf("invalid root signature %s != %s", hex.EncodeToString(sig.Sig), hex.EncodeToString(i.RootSignature.Sig))
	}
	return nil
}
