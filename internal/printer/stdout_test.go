package printer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, spiffeID string, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test-workload", Organization: []string{"Test Org"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestPrintSVID_ContainsExpectedFields(t *testing.T) {
	spiffeID := "spiffe://example.org/workload/test"
	cert, key := generateTestCert(t, spiffeID, time.Now().Add(24*time.Hour))

	var buf bytes.Buffer
	printSVID(&buf, spiffeID, "my-hint", cert, key)
	out := buf.String()

	checks := []string{
		spiffeID,
		"my-hint",
		"ECDSA P-256",
		"SHA256WithECDSA",
		"-----BEGIN PUBLIC KEY-----",
		"-----END PUBLIC KEY-----",
		"remaining",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestPrintSVID_NoHint(t *testing.T) {
	spiffeID := "spiffe://example.org/workload/nohint"
	cert, key := generateTestCert(t, spiffeID, time.Now().Add(time.Hour))

	var buf bytes.Buffer
	printSVID(&buf, spiffeID, "", cert, key)
	out := buf.String()

	if strings.Contains(out, "Hint") {
		t.Errorf("output should not contain Hint line when hint is empty:\n%s", out)
	}
}

func TestPrintSVID_Expired(t *testing.T) {
	spiffeID := "spiffe://example.org/workload/expired"
	cert, key := generateTestCert(t, spiffeID, time.Now().Add(-time.Hour))

	var buf bytes.Buffer
	printSVID(&buf, spiffeID, "", cert, key)
	out := buf.String()

	if !strings.Contains(out, "EXPIRED") {
		t.Errorf("output should contain EXPIRED:\n%s", out)
	}
}

func TestFormatRemaining(t *testing.T) {
	cases := []struct {
		dur  time.Duration
		want string
	}{
		{-time.Hour, "EXPIRED"},
		{30 * time.Minute, "30m remaining"},
		{2*time.Hour + 15*time.Minute, "2h 15m remaining"},
		{25*time.Hour + 3*time.Minute, "1d 1h 3m remaining"},
	}
	for _, tc := range cases {
		got := formatRemaining(time.Now().Add(tc.dur))
		if got != tc.want {
			t.Errorf("formatRemaining(%v) = %q, want %q", tc.dur, got, tc.want)
		}
	}
}
