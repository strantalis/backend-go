package tdf3

import (
	"crypto"

	"github.com/google/uuid"
)

type TDF struct {
	Payload               Payload               `json:"payload"`
	EncryptionInformation EncryptionInformation `json:"encryptionInformation"`
}

type EncryptionInformation struct {
	IntegrityInformation IntegrityInformation `json:"integrityInformation"`
	KeyAccess            []KeyAccess          `json:"keyAccess"`
	Method               EncryptionMethod     `json:"method"`
	Policy               []byte               `json:"policy"`
	Type                 string               `json:"type"`
}

type Signature struct {
	Alg string `json:"alg"`
	Sig []byte `json:"sig"`
}

type Segment struct {
	EncryptedSegmentSize int    `json:"encryptedSegmentSize"`
	Hash                 []byte `json:"hash"`
	SegmentSize          int    `json:"segmentSize"`
}

type IntegrityInformation struct {
	EncryptedSegmentSizeDefault int       `json:"encryptedSegmentSizeDefault"`
	RootSignature               Signature `json:"rootSignature"`
	SegmentHashAlg              string    `json:"segmentHashAlg"`
	SegmentSizeDefault          int       `json:"segmentSizeDefault"`
	Segments                    []Segment `json:"segments"`
}

type EncryptionMethod struct {
	Algorithm  string `json:"algorithm"`
	Streamable bool   `json:"isStreamable"`
	IV         []byte `json:"iv"`
}

type Payload struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	IsEncrypted bool   `json:"isEncrypted"`
	MimeType    string `json:"mimeType"`
	Version     string `json:"version"`
}

type Policy struct {
	UUID uuid.UUID `json:"uuid"`
	Body Body      `json:"body"`
}

type Body struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
}

type Attribute struct {
	URI           string           `json:"attribute"` // attribute
	PublicKey     crypto.PublicKey `json:"pubKey"`    // pubKey
	ProviderURI   string           `json:"kasUrl"`    // kasUrl
	SchemaVersion string           `json:"tdf_spec_version,omitempty"`
	Name          string           `json:"displayName"` // displayName
}
