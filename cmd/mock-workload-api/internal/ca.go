package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"
)

// CA is a self-signed ECDSA certificate authority used to issue SVID leaf certs.
type CA struct {
	Cert    *x509.Certificate
	CertDER []byte
	Key     *ecdsa.PrivateKey
}

// NewCA generates a new self-signed CA valid for ttl.
func NewCA(ttl time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Mock SPIFFE CA",
			Organization: []string{"spiffe-info Mock"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(ttl),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertDER: der, Key: key}, nil
}

// IssuedSVID holds the DER-encoded artifacts for one leaf SVID.
type IssuedSVID struct {
	CertDER   []byte // ASN.1 DER leaf certificate
	KeyDER    []byte // PKCS#8 ASN.1 DER private key
	BundleDER []byte // ASN.1 DER CA certificate (trust bundle)
}

// Issue creates a new leaf X.509-SVID for the given SPIFFE ID.
func (ca *CA) Issue(spiffeID string, ttl time.Duration) (*IssuedSVID, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}

	return &IssuedSVID{
		CertDER:   certDER,
		KeyDER:    keyDER,
		BundleDER: ca.CertDER,
	}, nil
}
