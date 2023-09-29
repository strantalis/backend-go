package client

import (
	"archive/zip"
	"bufio"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"dario.cat/mergo"
	"github.com/google/uuid"
	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"github.com/opentdf/backend-go/internal/kas"
	"github.com/opentdf/backend-go/pkg/tdf3"
)

const (
	profileName = iota
	oidcDiscoveryEndpoint
	kasEndpoint
	clientID
	clientSecret
)

const (
	payloadProtocolDefault string = "zip"
	segmentSizeDefault     int    = 1024 * 1024
	manifestFileName       string = "0.manifest.json"
)

type Client struct {
	kas     []*kas.Client
	PrivKey []byte
	PubKey  []byte
}

type TDFClientOptions struct {
	KasEndpoint []string
	PrivKey     []byte
	PubKey      []byte
	HttpClient  *http.Client
}

type TDFCreateOptions struct {
	Attributes         []tdf3.Attribute
	CryptoAlgorithm    tdfCrypto.CryptoAlgorithm
	EncryptedMetadata  []byte
	Dissem             []string
	UnencryptedPayload bool
	PayloadProtocol    string
	SegmentSize        int
	KeySplitType       string
	HashAlgorithm      crypto.Hash
}

func NewTDFClient(ops ...TDFClientOptions) (*Client, error) {
	client := &Client{}
	if len(ops) > 0 {
		client.PrivKey = ops[0].PrivKey
		client.PubKey = ops[0].PubKey

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

}

func (client Client) Create(content io.Reader, writer io.Writer, options *TDFCreateOptions) error {
	var (
		tdf tdf3.TDF
	)

	// Set TDFCreateOptions Default
	defaultOptions := &TDFCreateOptions{
		Attributes:      make([]tdf3.Attribute, 0),
		CryptoAlgorithm: tdfCrypto.AES256GCM,
		Dissem:          make([]string, 0),
		PayloadProtocol: payloadProtocolDefault,
		SegmentSize:     segmentSizeDefault,
		KeySplitType:    "split",
		HashAlgorithm:   crypto.SHA256,
	}

	// Override default options with user options
	if options != nil {
		err := mergo.Merge(defaultOptions, options, mergo.WithOverride)
		if err != nil {
			return err
		}
	}
	options = defaultOptions

	// Create new crypto provider
	cryptoProvider, err := tdfCrypto.NewCryptoClient(options.CryptoAlgorithm)
	if err != nil {
		return err
	}

	/*
	 Describe Payload Object
	*/
	// Allow different types of payloads when supported
	tdf.Payload.Type = "reference"
	// Location of payload whether thats in zip or remote (only zip supported for now)
	tdf.Payload.URL = "0.payload"
	tdf.Payload.Protocol = options.PayloadProtocol
	tdf.Payload.IsEncrypted = options.UnencryptedPayload

	// We should poke at Method. Still don't understand where this is used.
	tdf.EncryptionInformation.Method.Algorithm = options.CryptoAlgorithm.String()
	// What does streamable mean?
	tdf.EncryptionInformation.Method.Streamable = true
	// I don't think IV is needed or used
	tdf.EncryptionInformation.Method.IV = []byte("")

	tdfZip := zip.NewWriter(writer)

	var segments []tdf3.Segment
	segmentCount := 0

	// Define payload file in zip
	payload := &zip.FileHeader{
		Name:   fmt.Sprintf("%d.payload", 0),
		Method: zip.Store,
	}

	payloadWriter, err := tdfZip.CreateHeader(payload)
	if err != nil {
		return err
	}

	// Create buffer to read in data based on desired segment size
	buf := make([]byte, options.SegmentSize)

	// Wrap io.Reader in bufio.Reader
	bufReader := bufio.NewReaderSize(content, options.SegmentSize)
	// Chunk the payload and encrypt into segments
	for {
		n, err := bufReader.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		// Detect mime type from first chunk
		if segmentCount == 0 {
			tdf.Payload.MimeType = http.DetectContentType(buf[:n])
		}
		if n == 0 {
			break
		}

		// Encrypt segment
		cipherText, err := cryptoProvider.Encrypt(buf[:n])
		if err != nil {
			return err
		}

		// Build new segment
		segment := tdf3.Segment{}

		segment.Build(cipherText, cryptoProvider.Key())
		segments = append(segments, segment)

		if _, err := payloadWriter.Write(cipherText); err != nil {
			return err
		}

		segmentCount++

	}

	/*
		Build integrity information
	*/
	tdf.EncryptionInformation.IntegrityInformation.Segments = segments
	// GMAC means to use the gcm auth tag
	tdf.EncryptionInformation.IntegrityInformation.SegmentHashAlg = "GMAC"
	tdf.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = options.SegmentSize
	//
	tdf.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault = cryptoProvider.EncryptedSegmentSizeDefault(options.SegmentSize)

	// Build root signature from all the segments
	err = tdf.EncryptionInformation.IntegrityInformation.BuildRootSignature(cryptoProvider.Key())
	if err != nil {
		return err
	}

	//Build Policy Object
	policy := &tdf3.Policy{}
	// Why do we need a UUID if the policy isn't stored remotely?
	policy.UUID = uuid.New()
	policy.Body.DataAttributes = options.Attributes
	policy.Body.Dissem = options.Dissem

	jsonPolicy, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	tdf.EncryptionInformation.Policy = jsonPolicy
	b64Policy := base64.StdEncoding.EncodeToString(jsonPolicy)
	keySplits, err := tdfCrypto.KeySplit(options.KeySplitType, cryptoProvider.Key(), len(client.kas))
	if err != nil {
		return err
	}
	//Key Access Object Creation
	for i, k := range client.kas {
		var encryptedMetatDataCipherText []byte

		keyAccess := &tdf3.KeyAccess{}
		keyAccess.Type = "wrapped"
		keyAccess.URL = k.Endpoint.String()
		keyAccess.Protocol = "kas"

		keyAccess.WrappedKey, err = k.LocalRewrap(keySplits[i])
		if err != nil {
			return err
		}
		keyAccess.PolicyBinding = tdfCrypto.Sign(options.HashAlgorithm, []byte(b64Policy), keySplits[i])

		// Encrypted Meta Data
		if len(options.EncryptedMetadata) != 0 {
			var metadata tdf3.Metadata
			// Generate nonce or what some people call the iv
			metaDataCryptoProvider, err := tdfCrypto.NewCryptoClientWithKey(options.CryptoAlgorithm, keySplits[i])
			if err != nil {
				return err
			}

			metadata.Algorithm = metaDataCryptoProvider.Algorithm()

			// Encrypt segment
			metadata.CipherText, err = metaDataCryptoProvider.Encrypt(options.EncryptedMetadata)
			if err != nil {
				return err
			}

			// We shouldn't store IV like this
			metadata.IV = metadata.CipherText[:12]

			encryptedMetatDataCipherText, err = json.Marshal(metadata)
			if err != nil {
				return err
			}
		}

		keyAccess.EncryptedMetadata = encryptedMetatDataCipherText
		tdf.EncryptionInformation.KeyAccess = append(tdf.EncryptionInformation.KeyAccess, *keyAccess)

	}

	// We only split type for now. Not sure what it actually means
	tdf.EncryptionInformation.Type = options.KeySplitType

	manifestHeader := &zip.FileHeader{
		Name:   manifestFileName,
		Method: zip.Store,
	}
	manifestWriter, err := tdfZip.CreateHeader(manifestHeader)
	if err != nil {
		return err
	}
	manifest, err := json.Marshal(tdf)
	if err != nil {
		return err
	}
	if _, err := manifestWriter.Write(manifest); err != nil {
		return err
	}

	err = tdfZip.Close()
	if err != nil {
		return err
	}
	return nil
}

// GetPayload gets the encrypted payload within the tdf
func (client Client) GetPayload(reader io.ReaderAt, size int64, writer io.Writer) error {
	//Can we set the size of the buffer to the segment size?
	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}

	// We need to work with the manifest from the zip archive
	tdf, err := getManifest(tdfZip)
	if err != nil {
		return err
	}

	/*
		Start of KAS ReWrap Request to get data key that actually encrypts the content
	*/

	// Build kas rewrap request object

	privateKey, err := tdfCrypto.ParsePrivateKey(client.PrivKey)
	if err != nil {
		return err
	}

	var splits = make([][]byte, len(tdf.EncryptionInformation.KeyAccess)-1)
	// Get Split Keys
	for k, kao := range tdf.EncryptionInformation.KeyAccess {
		// Need to figure out how to handle other types
		if kao.Type == "wrapped" {
			var (
				rewrapRequest = new(kas.RequestBody)
			)
			rewrapRequest.KeyAccess = kao
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
	// Merge key splits back together
	payloadKey, err := tdfCrypto.KeyMerge(tdf.EncryptionInformation.Type, splits)
	if err != nil {
		return err
	}

	// Before we try to decrypt we need to valid the integrity of the rootSignature
	if err := tdf.EncryptionInformation.IntegrityInformation.Validate(payloadKey); err != nil {
		return err
	}
	alg, err := tdfCrypto.GetCryptoAlgorithm(tdf.EncryptionInformation.Method.Algorithm)
	if err != nil {
		return err
	}
	cryptoProvider, err := tdfCrypto.NewCryptoClientWithKey(alg, payloadKey)
	if err != nil {
		return err
	}

	// Wrap writer in bufio.Writer
	bufWriter := bufio.NewWriterSize(writer, tdf.EncryptionInformation.IntegrityInformation.SegmentSizeDefault)

	// Open Payload File
	payload, err := tdfZip.Open(tdf.Payload.URL)
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

		plainText, err := cryptoProvider.Decrypt(chunk)
		if err != nil {
			return errors.Join(errors.New("failed to decrypt segment"), err)
		}
		_, err = bufWriter.Write(plainText)
		if err != nil {
			return err
		}
	}

	err = bufWriter.Flush()
	if err != nil {
		return err
	}

	return nil
}

func getManifest(reader *zip.Reader) (*tdf3.TDF, error) {

	var tdf = new(tdf3.TDF)

	// Find the file in the zip archive based on its name.
	var targetFile *zip.File
	for _, file := range reader.File {
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

func (client Client) GetManifest(reader io.ReaderAt, size int64) (*tdf3.TDF, error) {

	tdfZip, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, err
	}
	return getManifest(tdfZip)

}

// this is a hack for hackathon
func (client Client) GetEncryptedMetaData(reader io.ReaderAt, size int64) ([]byte, error) {

	// We need to work with the manifest from the zip archive
	tdf, err := client.GetManifest(reader, size)
	if err != nil {
		return nil, err
	}

	privateKey, err := tdfCrypto.ParsePrivateKey(client.PrivKey)
	if err != nil {
		return nil, err
	}

	var splits = make([][]byte, len(tdf.EncryptionInformation.KeyAccess)-1)
	for k, kao := range tdf.EncryptionInformation.KeyAccess {
		// Need to figure out how to handle other types
		if kao.Type == "wrapped" {
			var (
				rewrapRequest = new(kas.RequestBody)
			)
			rewrapRequest.KeyAccess = kao
			rewrapRequest.ClientPublicKey = string(client.PubKey)
			rewrapRequest.Policy = tdf.EncryptionInformation.Policy
			rewrapResponse, err := client.kas[k].RemoteRewrap(rewrapRequest, privateKey)
			// Get Wrapped Key
			if err != nil {
				return nil, err
			}

			// Unwrap our key from KAS
			split, err := tdfCrypto.DecryptOAEP(privateKey.(*rsa.PrivateKey), rewrapResponse.EntityWrappedKey)
			if err != nil {
				return nil, err
			}
			splits = append(splits, split)
		}
	}
	// Merge key splits back together
	payloadKey, err := tdfCrypto.KeyMerge(tdf.EncryptionInformation.Type, splits)
	if err != nil {
		return nil, err
	}

	// Before we try to decrypt we need to valid the integrity of the rootSignature
	if err := tdf.EncryptionInformation.IntegrityInformation.Validate(payloadKey); err != nil {
		return nil, err
	}

	for _, kao := range tdf.EncryptionInformation.KeyAccess {
		if kao.EncryptedMetadata != nil {
			var metadata *tdf3.Metadata
			err = json.Unmarshal(kao.EncryptedMetadata, &metadata)
			if err != nil {
				return nil, err
			}
			alg, err := tdfCrypto.GetCryptoAlgorithm(tdf.EncryptionInformation.Method.Algorithm)
			if err != nil {
				return nil, err
			}
			metaDataCryptoProvider, err := tdfCrypto.NewCryptoClientWithKey(alg, payloadKey)
			if err != nil {
				return nil, err
			}

			pt, err := metaDataCryptoProvider.Decrypt(metadata.CipherText)
			if err != nil {
				return nil, errors.Join(errors.New("failed to decrypt encrypted metadata"), err)
			}
			return pt, nil
		}
	}

	return nil, errors.New("no encrypted metadata found")
}
