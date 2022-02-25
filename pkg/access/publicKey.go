package access

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"log"
	"net/http"
)

func (p *Provider) CertificateHandler(w http.ResponseWriter, r *http.Request) {	
	certificatePem, err := exportCertificateAsPemStr(&p.Certificate)
	if err != nil {
		log.Fatalf("error RSA public key from PKCS11: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	log.Println(certificatePem)

	jData, err := json.Marshal(certificatePem)
	if err != nil {
		log.Fatalf("error json certificate Marshal: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jData)
}


// PublicKeyHandlerV2 decrypts and encrypts the symmetric data key
func (p *Provider) PublicKeyHandlerV2(w http.ResponseWriter, r *http.Request) {
	algorithm := r.URL.Query().Get("algorithm")
	// ?algorithm=ec:secp256r1
	if algorithm == "ec:secp256r1" {
		ecPublicKeyPem, err := exportEcPublicKeyAsPemStr(&p.PublicKeyEc)
		if err != nil {
			log.Fatalf("error EC public key from PKCS11: %v", err)
		}
		log.Println(ecPublicKeyPem)
		_, _ = w.Write([]byte(ecPublicKeyPem))
		return
	}
	rsaPublicKeyPem, err := exportRsaPublicKeyAsPemStr(&p.PublicKeyRsa)
	if err != nil {
		log.Fatalf("error RSA public key from PKCS11: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	log.Println(rsaPublicKeyPem)
	_, _ = w.Write([]byte(rsaPublicKeyPem))
}

func exportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func exportEcPublicKeyAsPemStr(pubkey *ecdsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func exportCertificateAsPemStr(cert *x509.Certificate) (string, error) {
	certBytes := cert.Raw

	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		},
	)

	return string(certPem), nil
}
