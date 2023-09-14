package client

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/opentdf/backend-go/internal/crypto"
	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"github.com/opentdf/backend-go/internal/kas"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"golang.org/x/exp/slices"
)

const (
	encryptionAlgorithm string = "aes-%d-gcm"
	payloadProtocol     string = "zip"
	segmentSize         int    = 1024 * 1024
	manifestFileName    string = "0.manifest.json"
)

var (
	validKeyLength []int = []int{64, 128, 192, 256}
)

type Client struct {
	keyLength   int
	kas         []*kas.Client
	accessToken string
	PrivKey     []byte
	PubKey      []byte
}

type TDFClientOptions struct {
	KeyLength   *int
	KasEndpoint []string
	AccessToken string
	PrivKey     []byte
	PubKey      []byte
	HttpClient  *http.Client
}

func NewTDFClient(ops ...TDFClientOptions) (*Client, error) {
	client := &Client{}
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

		for _, endpoint := range ops[0].KasEndpoint {
			var (
				kasUrl *url.URL
				err    error
			)

			kasUrl, err = url.Parse(endpoint)
			if err != nil {
				return nil, err
			}

			if ops[0].HttpClient == nil {
				ops[0].HttpClient = http.DefaultClient
			}

			kc, err := kas.NewClient(kas.KasClientOptions{
				Endpoint:   kasUrl,
				HttpClient: ops[0].HttpClient,
			})
			if err != nil {
				return nil, err
			}
			client.kas = append(client.kas, kc)
		}
	}

	// Set defaults for options not set
	clientDefaults(client)
	return client, nil
}

func clientDefaults(client *Client) {
	if client.keyLength == 0 {
		client.keyLength = 256
	}
}

func (client *Client) Create(plainText io.Reader, attributes []tdf3.Attribute, encrypionType string) ([]byte, error) {
	keyLength := client.keyLength / 8

	var (
		tdf        tdf3.TDF
		payloadKey = make([]byte, keyLength)
	)
	encrypionType = "split"
	// Generate new payload key
	// Divide by 8 to get bytes
	payloadKey, err := tdfCrypto.GenerateKey(keyLength)
	if err != nil {
		return nil, err
	}

	gcm, err := tdfCrypto.NewGCM(payloadKey)
	if err != nil {
		return nil, err
	}

	// Describe Payload
	tdf.Payload.Type = "reference"
	tdf.Payload.URL = "0.payload"
	tdf.Payload.Protocol = payloadProtocol
	tdf.Payload.IsEncrypted = true

	// We should poke at Method. Still don't understand where this is used.
	tdf.EncryptionInformation.Method.Algorithm = fmt.Sprintf(encryptionAlgorithm, client.keyLength)
	// What does streamable mean?
	tdf.EncryptionInformation.Method.Streamable = true
	// I don't think IV is needed or used
	tdf.EncryptionInformation.Method.IV = []byte("")

	zipBuf := new(bytes.Buffer)
	tdfZip := zip.NewWriter(zipBuf)

	buf := make([]byte, segmentSize)
	var segments []tdf3.Segment
	chunkCount := 0

	// Define payload file in zip
	payload := &zip.FileHeader{
		Name:   fmt.Sprintf("%d.payload", 0),
		Method: zip.Store,
	}

	chunkWriter, err := tdfZip.CreateHeader(payload)
	if err != nil {
		return nil, err
	}

	// Chunk the payload and encrypt into segments
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

		// Generate nonce or what some people call the iv
		nonce, err := tdfCrypto.GenerateNonce(gcm.NonceSize())
		if err != nil {
			return nil, err
		}

		// Encrypt segment
		cipherText := gcm.Seal(nonce, nonce, buf[:n], nil)

		// Build new segment
		segment := tdf3.Segment{}

		segment.Build(cipherText, payloadKey)
		segments = append(segments, segment)

		chunkWriter.Write(cipherText)

		chunkCount++

	}

	// Build integrity information
	tdf.EncryptionInformation.IntegrityInformation.Segments = segments
	tdf.EncryptionInformation.IntegrityInformation.SegmentHashAlg = "GMAC"
	tdf.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = segmentSize
	tdf.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault = segmentSize + gcm.NonceSize() + 16 // 16 is for auth tag

	err = tdf.EncryptionInformation.IntegrityInformation.BuildRootSignature(payloadKey)
	if err != nil {
		return nil, err
	}

	//TODO: Build Policy Object
	policy := &tdf3.Policy{}
	policy.UUID = uuid.New()
	policy.Body.DataAttributes = attributes
	policy.Body.Dissem = make([]string, 0)

	jsonPolicy, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}

	tdf.EncryptionInformation.Policy = jsonPolicy
	b64Policy := base64.StdEncoding.EncodeToString(jsonPolicy)
	// How does actually get validated by the kas?
	// How do we actually use multiple key access objects?
	//Key Access
	switch encrypionType {
	case "split":
		splits := crypto.KeySplit(payloadKey, len(client.kas))
		for i, kas := range client.kas {

			keyAccess := &tdf3.KeyAccess{}
			keyAccess.Type = "wrapped"
			keyAccess.URL = kas.Endpoint.String()
			keyAccess.Protocol = "kas"

			keyAccess.WrappedKey, err = kas.LocalRewrap(splits[i])
			if err != nil {
				return nil, err
			}
			keyAccess.PolicyBinding = tdfCrypto.Sign([]byte(b64Policy), splits[i])
			tdf.EncryptionInformation.KeyAccess = append(tdf.EncryptionInformation.KeyAccess, *keyAccess)

		}
	case "shamir":
		fmt.Println("TODO: shamir")
	default:
		fmt.Println("Not a valid encryption type")

	}

	// We only split type for now. Not sure what it actually means
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

// We should probably accept an IO Writer Interface here as well
func (client *Client) GetContent(file io.Reader, writer io.Writer) error {
	//Can we set the size of the buffer to the segment size?
	buff := bytes.NewBuffer([]byte{})

	// Is this the best way to get the size of the file?
	size, err := io.Copy(buff, file)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(buff.Bytes())
	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}

	// We need to work with the manifest from the zip archive
	tdf, err := client.GetManifest(buff)
	if err != nil {
		return err
	}

	/*
		Start of KAS ReWrap Request to get data key that actually encrypts the content
	*/

	// Build kas rewrap request object
	// keyAccessObjs := tdf.EncryptionInformation.Key()

	privateKey, err := tdfCrypto.ParsePrivateKey(client.PrivKey)
	if err != nil {
		return err
	}

	var payloadKey []byte
	switch tdf.EncryptionInformation.Type {
	case "split":
		var splits [][]byte
		for k, ka := range tdf.EncryptionInformation.KeyAccess {
			// Need to figure out how to handle other types
			if ka.Type == "wrapped" {
				var (
					rewrapRequest = new(kas.RequestBody)
				)
				rewrapRequest.KeyAccess = ka
				rewrapRequest.ClientPublicKey = string(client.PubKey)
				rewrapRequest.Policy = tdf.EncryptionInformation.Policy
				rewrapResponse, err := client.kas[k].RemoteRewrap(rewrapRequest, privateKey)
				// Get Wrapped Key
				if err != nil {
					return err
				}

				// Unwrap our key from KAS
				split, err := tdfCrypto.DecryptOAEP(privateKey.(*rsa.PrivateKey), rewrapResponse.EntityWrappedKey)
				if err != nil {
					return err
				}
				splits = append(splits, split)
			}
		}
		payloadKey = crypto.KeyMerge(splits)
	case "shamir":
		fmt.Println("TODO: shamir")
	default:
		fmt.Println("Not a valid encryption type")

	}

	// Before we try to decrypt we need to valid the integrity of the rootSignature
	if err := tdf.EncryptionInformation.IntegrityInformation.Validate(payloadKey); err != nil {
		return err
	}

	gcm, err := tdfCrypto.NewGCM(payloadKey)
	if err != nil {
		return err
	}

	// Open Payload File
	payload, err := tdfZip.Open("0.payload")
	if err != nil {
		return err
	}
	defer payload.Close()

	for _, segment := range tdf.EncryptionInformation.IntegrityInformation.Segments {
		// Read the next chunk
		chunk := make([]byte, segment.EncryptedSegmentSize)

		_, err := payload.Read(chunk)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		nonce, cipherText := chunk[:gcm.NonceSize()], chunk[gcm.NonceSize():]
		pt, err := gcm.Open(nil, nonce, cipherText, nil)
		if err != nil {
			return errors.Join(errors.New("failed to decrypt segment"), err)
		}
		_, err = writer.Write(pt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (client *Client) GetManifest(file io.Reader) (tdf3.TDF, error) {
	var tdf tdf3.TDF

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
