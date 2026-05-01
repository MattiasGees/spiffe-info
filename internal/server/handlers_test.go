package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// mockStore implements workload.Store for tests.
type mockStore struct {
	x509ctx *workloadapi.X509Context
	jwtSVID *jwtsvid.SVID
	jwtErr  error
}

func (m *mockStore) CurrentX509Context() *workloadapi.X509Context { return m.x509ctx }
func (m *mockStore) FetchJWTSVID(_ context.Context, _ string) (*jwtsvid.SVID, error) {
	return m.jwtSVID, m.jwtErr
}

func buildTestX509Context(t *testing.T) (*workloadapi.X509Context, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://example.org/workload/test")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	id, err := spiffeid.FromString("spiffe://example.org/workload/test")
	if err != nil {
		t.Fatal(err)
	}
	svid := &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{cert},
		PrivateKey:   key,
	}

	td := id.TrustDomain()
	bundle := x509bundle.New(td)
	bundle.AddX509Authority(cert)

	return &workloadapi.X509Context{
		SVIDs:   []*x509svid.SVID{svid},
		Bundles: x509bundle.NewSet(bundle),
	}, key
}

func TestHandleX509SVID_OK(t *testing.T) {
	ctx, _ := buildTestX509Context(t)
	h := &handlers{store: &mockStore{x509ctx: ctx}, jwtAudience: "spiffe-info"}

	req := httptest.NewRequest(http.MethodGet, "/api/x509-svid", nil)
	rec := httptest.NewRecorder()
	h.handleX509SVID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp x509SVIDResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.SpiffeID != "spiffe://example.org/workload/test" {
		t.Errorf("unexpected spiffeId: %q", resp.SpiffeID)
	}
	if resp.KeyAlgorithm != "ECDSA P-256" {
		t.Errorf("unexpected keyAlgorithm: %q", resp.KeyAlgorithm)
	}
	if resp.PEM == "" {
		t.Error("PEM should not be empty")
	}
	if resp.PublicKeyPEM == "" {
		t.Error("publicKeyPem should not be empty")
	}
}

func TestHandleX509SVID_NoData(t *testing.T) {
	h := &handlers{store: &mockStore{}, jwtAudience: "spiffe-info"}
	req := httptest.NewRequest(http.MethodGet, "/api/x509-svid", nil)
	rec := httptest.NewRecorder()
	h.handleX509SVID(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleTrustBundles_OK(t *testing.T) {
	ctx, _ := buildTestX509Context(t)
	h := &handlers{store: &mockStore{x509ctx: ctx}, jwtAudience: "spiffe-info"}

	req := httptest.NewRequest(http.MethodGet, "/api/trust-bundles", nil)
	rec := httptest.NewRecorder()
	h.handleTrustBundles(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var bundles []trustBundleCert
	if err := json.NewDecoder(rec.Body).Decode(&bundles); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if len(bundles) == 0 {
		t.Error("expected at least one bundle cert")
	}
	if bundles[0].TrustDomain != "example.org" {
		t.Errorf("unexpected trustDomain: %q", bundles[0].TrustDomain)
	}
}

func TestHandleTrustBundles_NoData(t *testing.T) {
	h := &handlers{store: &mockStore{}, jwtAudience: "spiffe-info"}
	req := httptest.NewRequest(http.MethodGet, "/api/trust-bundles", nil)
	rec := httptest.NewRecorder()
	h.handleTrustBundles(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestHandleJWTSVID_Error(t *testing.T) {
	h := &handlers{
		store:       &mockStore{jwtErr: context.DeadlineExceeded},
		jwtAudience: "spiffe-info",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/jwt-svid", nil)
	rec := httptest.NewRecorder()
	h.handleJWTSVID(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}
