package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// JWTIssuer signs JWT-SVIDs using ECDSA ES256.
type JWTIssuer struct {
	key    *ecdsa.PrivateKey
	KeyID  string
	Issuer string
}

// NewJWTIssuer creates a new JWTIssuer with a freshly generated ECDSA P-256 key.
func NewJWTIssuer(issuer string) (*JWTIssuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &JWTIssuer{key: key, KeyID: "mock-key-1", Issuer: issuer}, nil
}

// NewJWTIssuerFromKey creates a JWTIssuer using an existing ECDSA key.
func NewJWTIssuerFromKey(key *ecdsa.PrivateKey, keyID, issuer string) *JWTIssuer {
	return &JWTIssuer{key: key, KeyID: keyID, Issuer: issuer}
}

// Issue returns a signed compact JWT-SVID token.
func (j *JWTIssuer) Issue(subject string, audiences []string, ttl time.Duration) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: j.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", j.KeyID),
	)
	if err != nil {
		return "", fmt.Errorf("creating signer: %w", err)
	}

	now := time.Now()
	claims := josejwt.Claims{
		Subject:  subject,
		Issuer:   j.Issuer,
		Audience: josejwt.Audience(audiences),
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(ttl)),
		ID:       generateJTI(),
	}

	return josejwt.Signed(sig).Claims(claims).Serialize()
}

// JWKSBytes returns the public key as a JSON-encoded JWKS.
func (j *JWTIssuer) JWKSBytes() ([]byte, error) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &j.key.PublicKey,
				KeyID:     j.KeyID,
				Algorithm: string(jose.ES256),
				Use:       "sig",
			},
		},
	}
	return json.Marshal(jwks)
}

func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
