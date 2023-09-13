package tdf3

type TDF struct {
	Payload               Payload               `json:"payload"`
	EncryptionInformation EncryptionInformation `json:"encryptionInformation"`
}

type Payload struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	IsEncrypted bool   `json:"isEncrypted"`
	MimeType    string `json:"mimeType"`
	Version     string `json:"version"`
}

type EncryptionInformation struct {
	IntegrityInformation IntegrityInformation `json:"integrityInformation"`
	KeyAccess            []KeyAccess          `json:"keyAccess"`
	Method               EncryptionMethod     `json:"method"`
	Policy               []byte               `json:"policy"`
	Type                 string               `json:"type"`
}

type EncryptionMethod struct {
	Algorithm  string `json:"algorithm"`
	Streamable bool   `json:"isStreamable"`
	IV         []byte `json:"iv"`
}

func (k *EncryptionInformation) FindRewraps() []KeyAccess {
	var rewraps []KeyAccess
	for _, ka := range k.KeyAccess {
		// What do we do if we have multiple rewraps in the key access?
		if ka.Type == "rewrap" {
			rewraps = append(rewraps, ka)
			return rewraps
		}
		if ka.Type == "split" {
			rewraps = append(rewraps, ka)
		}
	}
	return rewraps
}
