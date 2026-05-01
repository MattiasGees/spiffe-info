package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/mattiasGees/spiffe-info/internal/workload"
)

type handlers struct {
	store       workload.Store
	jwtAudience string
}

// ── JSON response types ──────────────────────────────────────────────────────

type x509SVIDResponse struct {
	SpiffeID           string   `json:"spiffeId"`
	Hint               string   `json:"hint"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serialNumber"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SubjectAltNames    []string `json:"subjectAltNames"`
	KeyAlgorithm       string   `json:"keyAlgorithm"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	KeyUsage           []string `json:"keyUsage"`
	ExtKeyUsage        []string `json:"extKeyUsage"`
	IsCA               bool     `json:"isCA"`
	Fingerprint        string   `json:"fingerprint"`
	PEM                string   `json:"pem"`
	PublicKeyPEM       string   `json:"publicKeyPem"`
}

type jwtSVIDResponse struct {
	SpiffeID  string                 `json:"spiffeId"`
	Hint      string                 `json:"hint"`
	Audience  []string               `json:"audience"`
	Token     string                 `json:"token"`
	Claims    map[string]interface{} `json:"claims"`
	Algorithm string                 `json:"algorithm"`
	KeyID     string                 `json:"keyId"`
}

type trustBundleCert struct {
	ID                 string `json:"id"`
	TrustDomain        string `json:"trustDomain"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	SerialNumber       string `json:"serialNumber"`
	NotBefore          string `json:"notBefore"`
	NotAfter           string `json:"notAfter"`
	KeyAlgorithm       string `json:"keyAlgorithm"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	Fingerprint        string `json:"fingerprint"`
	IsCA               bool   `json:"isCA"`
	PEM                string `json:"pem"`
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func (h *handlers) handleX509SVID(w http.ResponseWriter, r *http.Request) {
	ctx := h.store.CurrentX509Context()
	if ctx == nil || len(ctx.SVIDs) == 0 {
		http.Error(w, "workload API not yet connected", http.StatusServiceUnavailable)
		return
	}
	svid := ctx.SVIDs[0]
	if len(svid.Certificates) == 0 {
		http.Error(w, "no certificates in SVID", http.StatusServiceUnavailable)
		return
	}
	cert := svid.Certificates[0]

	pubKeyPEM, _ := marshalPublicKey(svid.PrivateKey.Public())

	resp := x509SVIDResponse{
		SpiffeID:           svid.ID.String(),
		Hint:               svid.Hint,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       formatSerial(cert.SerialNumber),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		SubjectAltNames:    subjectAltNames(cert),
		KeyAlgorithm:       keyAlgorithmName(cert),
		SignatureAlgorithm: sigAlgorithmName(cert),
		KeyUsage:           keyUsages(cert),
		ExtKeyUsage:        extKeyUsages(cert),
		IsCA:               cert.IsCA,
		Fingerprint:        certFingerprint(cert),
		PEM:                certToPEM(cert),
		PublicKeyPEM:       pubKeyPEM,
	}
	writeJSON(w, resp)
}

func (h *handlers) handleJWTSVID(w http.ResponseWriter, r *http.Request) {
	svid, err := h.store.FetchJWTSVID(r.Context(), h.jwtAudience)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch JWT-SVID: %v", err), http.StatusServiceUnavailable)
		return
	}

	token := svid.Marshal()
	alg, kid := decodeJWTHeader(token)

	// Normalise aud to always be []string
	claims := normaliseClaims(svid.Claims)

	resp := jwtSVIDResponse{
		SpiffeID:  svid.ID.String(),
		Hint:      svid.Hint,
		Audience:  svid.Audience,
		Token:     token,
		Claims:    claims,
		Algorithm: alg,
		KeyID:     kid,
	}
	writeJSON(w, resp)
}

func (h *handlers) handleTrustBundles(w http.ResponseWriter, r *http.Request) {
	ctx := h.store.CurrentX509Context()
	if ctx == nil || ctx.Bundles == nil {
		http.Error(w, "workload API not yet connected", http.StatusServiceUnavailable)
		return
	}

	var result []trustBundleCert
	for _, bundle := range ctx.Bundles.Bundles() {
		td := bundle.TrustDomain().String()
		for i, cert := range bundle.X509Authorities() {
			result = append(result, trustBundleCert{
				ID:                 fmt.Sprintf("%s-%d", td, i),
				TrustDomain:        td,
				Subject:            cert.Subject.String(),
				Issuer:             cert.Issuer.String(),
				SerialNumber:       formatSerial(cert.SerialNumber),
				NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
				KeyAlgorithm:       keyAlgorithmName(cert),
				SignatureAlgorithm: sigAlgorithmName(cert),
				Fingerprint:        certFingerprint(cert),
				IsCA:               cert.IsCA,
				PEM:                certToPEM(cert),
			})
		}
	}
	if result == nil {
		result = []trustBundleCert{}
	}
	writeJSON(w, result)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func formatSerial(n *big.Int) string {
	h := fmt.Sprintf("%X", n)
	if len(h)%2 != 0 {
		h = "0" + h
	}
	parts := make([]string, len(h)/2)
	for i := range parts {
		parts[i] = h[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := fmt.Sprintf("%X", sum)
	parts := make([]string, len(h)/2)
	for i := range parts {
		parts[i] = h[i*2 : i*2+2]
	}
	return "SHA-256: " + strings.Join(parts, ":")
}

func certToPEM(cert *x509.Certificate) string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return buf.String()
}

func marshalPublicKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return buf.String(), nil
}

func subjectAltNames(cert *x509.Certificate) []string {
	var sans []string
	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}
	for _, d := range cert.DNSNames {
		sans = append(sans, d)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return sans
}

func keyAlgorithmName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return fmt.Sprintf("RSA %d", k.N.BitLen())
		}
		return "RSA"
	case x509.ECDSA:
		if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
		}
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func sigAlgorithmName(cert *x509.Certificate) string {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.ECDSAWithSHA256:
		return "SHA256WithECDSA"
	case x509.ECDSAWithSHA384:
		return "SHA384WithECDSA"
	case x509.ECDSAWithSHA512:
		return "SHA512WithECDSA"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return cert.SignatureAlgorithm.String()
	}
}

func keyUsages(cert *x509.Certificate) []string {
	var usages []string
	bits := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
	}
	for _, b := range bits {
		if cert.KeyUsage&b.bit != 0 {
			usages = append(usages, b.name)
		}
	}
	return usages
}

func extKeyUsages(cert *x509.Certificate) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "TLS Web Server Authentication",
		x509.ExtKeyUsageClientAuth:      "TLS Web Client Authentication",
		x509.ExtKeyUsageCodeSigning:     "Code Signing",
		x509.ExtKeyUsageEmailProtection: "Email Protection",
		x509.ExtKeyUsageTimeStamping:    "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
	}
	var out []string
	for _, u := range cert.ExtKeyUsage {
		if name, ok := names[u]; ok {
			out = append(out, name)
		}
	}
	return out
}

func decodeJWTHeader(token string) (alg, kid string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return "", ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ""
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	json.Unmarshal(b, &h)
	return h.Alg, h.Kid
}

func normaliseClaims(claims map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(claims))
	for k, v := range claims {
		if k == "aud" {
			switch a := v.(type) {
			case string:
				out[k] = []string{a}
			case []interface{}:
				strs := make([]string, len(a))
				for i, s := range a {
					strs[i] = fmt.Sprint(s)
				}
				out[k] = strs
			default:
				out[k] = v
			}
		} else {
			out[k] = v
		}
	}
	return out
}
