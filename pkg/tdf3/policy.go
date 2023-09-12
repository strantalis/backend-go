package tdf3

import (
	"crypto"

	"github.com/google/uuid"
)

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
