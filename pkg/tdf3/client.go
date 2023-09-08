package tdf3

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"golang.org/x/exp/slices"
)

const (
	encryptionAlgorithm string = "aes-%d-gcm"
	payloadProtocol     string = "zip"
	segmentSize         int    = 5242880
	manifestFileName    string = "0.manifest.json"
)

var (
	validKeyLength []int = []int{128, 192, 256}
)

type TDFClient struct {
	keyLength   int
	kasEndpoint string
	accessToken string
	PrivKey     []byte
	PubKey      []byte
}

type TDFClientOptions struct {
	KeyLength   *int
	KasEndpoint string
	AccessToken string
	PrivKey     []byte
	PubKey      []byte
}

type RewrapRequest struct {
	// AuthToken          string    `json:"authToken"`
	KeyAccess       KeyAccess `json:"keyAccess"`
	Policy          []byte    `json:"policy,omitempty"`
	Algorithm       string    `json:"algorithm,omitempty"`
	ClientPublicKey string    `json:"clientPublicKey"`
	// SchemaVersion      string `json:"schemaVersion,omitempty"`
}

type SignedRewrapRequest struct {
	SignedRequestToken string `json:"signedRequestToken"`
}

type RewrapResponse struct {
	EntityWrappedKey []byte `json:"entityWrappedKey"`
	SessionPublicKey string `json:"sessionPublicKey"`
	SchemaVersion    string `json:"schemaVersion,omitempty"`
}

func NewTDFClient(ops ...TDFClientOptions) (*TDFClient, error) {
	client := &TDFClient{}
	if len(ops) > 0 {
		client.accessToken = ops[0].AccessToken
		client.PrivKey = ops[0].PrivKey
		client.PubKey = ops[0].PubKey
		if ops[0].KeyLength != nil && !slices.Contains(validKeyLength, *ops[0].KeyLength) {
			return nil, errors.New("invalid key length. must be 128, 192, or 256")
		}
		if ops[0].KeyLength != nil {
			client.keyLength = *ops[0].KeyLength
		}
		if ops[0].KasEndpoint != "" {
			client.kasEndpoint = ops[0].KasEndpoint
		}
	}

	// Set defaults for options not set
	clientDefaults(client)
	return client, nil
}

func clientDefaults(client *TDFClient) {
	if client.keyLength == 0 {
		client.keyLength = 256
	}
	if client.kasEndpoint == "" {
		client.kasEndpoint = "http://localhost:8080"
	}
}

func (client *TDFClient) GenerateTDF(plainText io.Reader) ([]byte, error) {
	var (
		tdf TDF
	)

	// Generate new payload key
	// Divide by 8 to get bytes
	key, err := tdfCrypto.GenerateKey(client.keyLength / 8)
	if err != nil {
		return nil, err
	}

	fmt.Println("key: ", base64.StdEncoding.EncodeToString(key))

	gcm, err := tdfCrypto.NewGCM(key)
	if err != nil {
		return nil, err
	}

	tdf.EncryptionInformation.Method.Algorithm = fmt.Sprintf(encryptionAlgorithm, client.keyLength)
	iv, err := tdfCrypto.GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	tdf.EncryptionInformation.Method.IV = iv
	tdf.Payload.Type = "reference"
	tdf.Payload.URL = "0.payload"
	tdf.Payload.Protocol = payloadProtocol

	zipBuf := new(bytes.Buffer)
	tdfZip := zip.NewWriter(zipBuf)

	buf := make([]byte, segmentSize)
	var segments []Segment
	chunkCount := 0

	for {
		n, err := plainText.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		// Detect mime type from first chunk
		if chunkCount == 0 {
			tdf.Payload.MimeType = http.DetectContentType(buf[:n])
		}
		if n == 0 {
			break
		}

		// nonce, err := tdfCrypto.GenerateNonce(gcm.NonceSize())
		// if err != nil {
		// 	return nil, err
		// }

		p := tdfCrypto.Pad(buf[:n], aes.BlockSize)
		cipherText := gcm.Seal(nil, iv, p, nil)
		// Append nonce to cipher text
		// cipherText = append(cipherText, nonce...)
		segment := generateSegment(cipherText, key)
		segments = append(segments, segment)

		chunk := &zip.FileHeader{
			Name:   fmt.Sprintf("%d.payload", chunkCount),
			Method: zip.Store,
		}

		chunkWriter, err := tdfZip.CreateHeader(chunk)
		if err != nil {
			return nil, err
		}
		chunkWriter.Write(cipherText)

		chunkCount++
	}

	tdf.EncryptionInformation.IntegrityInformation.Segments = segments
	tdf.EncryptionInformation.IntegrityInformation.SegmentHashAlg = "GMAC"
	tdf.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = segmentSize
	tdf.EncryptionInformation.IntegrityInformation.RootSignature, err = generateRootSignature(segments, key)
	if err != nil {
		return nil, err
	}

	//Key Access
	keyAccess := &KeyAccess{}
	keyAccess.Type = "wrapped"
	keyAccess.URL = client.kasEndpoint
	keyAccess.Protocol = "kas"
	endpoint := fmt.Sprintf("%s/%s", client.kasEndpoint, "kas_public_key")
	req, _ := http.NewRequest("GET", endpoint, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var kasKey string
	err = json.NewDecoder(resp.Body).Decode(&kasKey)
	if err != nil {
		return nil, err
	}
	pemKey, _ := pem.Decode([]byte(kasKey))
	if pemKey == nil {
		return nil, errors.New("invalid pem key")
	}

	pub, err := x509.ParseCertificate(pemKey.Bytes)
	if err != nil {
		return nil, err
	}
	//Should probably validate pub type
	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub.PublicKey.(*rsa.PublicKey), key, nil)
	if err != nil {
		return nil, err
	}
	keyAccess.WrappedKey = wrappedKey
	tdf.EncryptionInformation.KeyAccess = append(tdf.EncryptionInformation.KeyAccess, *keyAccess)
	// end keyAccess

	// policy
	policy := &Policy{}
	policy.UUID = uuid.New()
	policy.Body.DataAttributes = make([]Attribute, 0)
	policy.Body.Dissem = make([]string, 0)

	jsonPolicy, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	fmt.Println("policy: ", string(jsonPolicy))
	tdf.EncryptionInformation.Policy = jsonPolicy
	b64Policy := base64.StdEncoding.EncodeToString(jsonPolicy)
	hpb := tdfCrypto.Sign([]byte(b64Policy), key)
	tdf.EncryptionInformation.KeyAccess[0].PolicyBinding = []byte(hex.EncodeToString(hpb))

	tdf.EncryptionInformation.Type = "split"

	manifestHeader := &zip.FileHeader{
		Name:   manifestFileName,
		Method: zip.Store,
	}
	manifestWriter, err := tdfZip.CreateHeader(manifestHeader)
	if err != nil {
		return nil, err
	}
	tdfb, err := json.Marshal(tdf)
	if err != nil {
		return nil, err
	}
	manifestWriter.Write(tdfb)

	err = tdfZip.Close()
	if err != nil {
		return nil, err
	}
	return zipBuf.Bytes(), nil
}

func (client *TDFClient) GetContent(file io.Reader, encKey string) ([]byte, error) {
	buff := bytes.NewBuffer([]byte{})
	size, err := io.Copy(buff, file)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(buff.Bytes())
	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, err
	}

	tdf, err := client.GetManifest(buff)
	if err != nil {
		return nil, err
	}

	var (
		rewrapRequest  RewrapRequest
		rewrapResponse RewrapResponse
	)

	// Rewrap
	rewrapRequest.KeyAccess = tdf.EncryptionInformation.KeyAccess[0]
	// _, pubKey, err := tdfCrypto.GenerateRSAKeysPem(2048)
	// if err != nil {
	// 	return nil, err
	// }
	rewrapRequest.ClientPublicKey = string(client.PubKey)

	rewrapRequest.Policy = tdf.EncryptionInformation.Policy

	// tok, err := jwt.Parse([]byte(accessToken), jwt.WithVerify(false))
	// if err != nil {
	// 	fmt.Printf("failed to parse token: %s\n", err)
	// 	return nil, err
	// }

	block, _ := pem.Decode([]byte(client.PrivKey))
	if block == nil {
		fmt.Println("Error decoding PEM block")
		return nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error parsing private key: %v\n", err)
		return nil, err
	}

	// pk, err := jwk.ParseKey(privKey)
	// if err != nil {
	// 	fmt.Printf("failed to parse JWK: %s\n", err)
	// 	return nil, err
	// }
	br, err := json.Marshal(rewrapRequest)
	if err != nil {
		return nil, err
	}
	requestBody := jwt.New()
	requestBody.Set("exp", time.Now().Add(time.Minute*5).Unix())
	requestBody.Set("requestBody", string(br))
	signed, err := jwt.Sign(requestBody, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return nil, err
	}
	signedRequestToken := &SignedRewrapRequest{SignedRequestToken: string(signed)}
	jsonBody, err := json.Marshal(signedRequestToken)
	if err != nil {
		return nil, err
	}
	reqBody := bytes.NewReader(jsonBody)
	fmt.Println("rewrap request: ", string(jsonBody))
	fmt.Println(fmt.Sprintf("%s/%s", tdf.EncryptionInformation.KeyAccess[0].URL, "v2/rewrap"))
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", tdf.EncryptionInformation.KeyAccess[0].URL, "v2/rewrap"), reqBody)
	// req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", "http://localhost:8080", "v2/rewrap"), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.accessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		fmt.Println("body: ", string(b))
		return nil, errors.New(fmt.Sprintf("rewrap failed with status code: %d", resp.StatusCode))
	}

	err = json.NewDecoder(resp.Body).Decode(&rewrapResponse)
	if err != nil {
		return nil, err
	}
	fmt.Println("rewrapped key: ", string(rewrapResponse.EntityWrappedKey))
	unwrapped, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey.(*rsa.PrivateKey), rewrapResponse.EntityWrappedKey, nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("unwrapped key: ", string(unwrapped))
	//TODO: REMOVE KEY
	// key, err := base64.StdEncoding.DecodeString(encKey)
	// if err != nil {
	// 	return nil, err
	// }
	gcm, err := tdfCrypto.NewGCM(unwrapped)
	if err != nil {
		return nil, err
	}

	var plainText []byte
	for _, file := range tdfZip.File {
		if file.Name == manifestFileName {
			fmt.Println("skipping manifest")
			continue
		}
		fmt.Println("file: ", file.Name)
		encryptedSegment, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer encryptedSegment.Close()
		cipherText, err := io.ReadAll(encryptedSegment)
		if err != nil {
			return nil, err
		}
		fmt.Println(string(cipherText))
		// Extract nonce from cipher text
		// nonce := cipherText[len(cipherText)-gcm.NonceSize():]
		// cipherText = cipherText[:len(cipherText)-gcm.NonceSize()]
		nonce := tdf.EncryptionInformation.Method.IV
		fmt.Println("nonce: ", string(nonce))
		//segment := manifest.EncryptedInformation.IntegrityInformation.Segments[i]
		pt, err := gcm.Open(nil, nonce, cipherText, nil)
		if err != nil {
			return nil, err
		}
		p, err := tdfCrypto.UnPad(pt)
		if err != nil {
			return nil, err
		}
		plainText = append(plainText, p...)
	}

	return plainText, nil
}

func (client *TDFClient) GetManifest(file io.Reader) (TDF, error) {
	var tdf TDF

	buff := bytes.NewBuffer([]byte{})
	size, err := io.Copy(buff, file)
	if err != nil {
		return tdf, err
	}

	reader := bytes.NewReader(buff.Bytes())
	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return tdf, err
	}

	// Find the file in the zip archive based on its name.
	var targetFile *zip.File
	for _, file := range tdfZip.File {
		if file.Name == manifestFileName {
			targetFile = file
			break
		}
	}
	if targetFile == nil {
		return tdf, errors.New("manifest.json not found")
	}
	targetFileReader, err := targetFile.Open()
	if err != nil {
		return tdf, err
	}
	defer targetFileReader.Close()
	content, err := io.ReadAll(targetFileReader)
	if err != nil {
		return tdf, err
	}

	err = json.Unmarshal(content, &tdf)
	if err != nil {
		return tdf, err
	}

	return tdf, nil
}

// What do we actually use to generate the root signature
func generateRootSignature(segments []Segment, key []byte) (Signature, error) {
	var rootSignature Signature
	rootSignature.Alg = "HS256"

	var toSign []byte
	for _, segment := range segments {
		toSign = append(toSign, segment.Hash...)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(toSign)

	rootSignature.Sig = mac.Sum(nil)

	return rootSignature, nil
}

func generateSegment(content []byte, key []byte) Segment {
	var segment Segment
	segment.SegmentSize = segmentSize
	segment.EncryptedSegmentSize = len(content)
	segment.Hash = tdfCrypto.Sign(content, key)
	return segment
}
