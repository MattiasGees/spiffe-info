package chain

import (
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

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string, parent *issuer) *issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{cert: cert, key: key}
}

func newLeaf(t *testing.T, id string, parent *issuer) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

const testID = "spiffe://example.org/workload/test"

func svidFor(t *testing.T, certs []*x509.Certificate, key *ecdsa.PrivateKey) *x509svid.SVID {
	t.Helper()
	id, err := spiffeid.FromString(testID)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: id, Certificates: certs, PrivateKey: key}
}

func bundleOf(t *testing.T, authorities ...*x509.Certificate) *x509bundle.Set {
	t.Helper()
	b := x509bundle.New(spiffeid.RequireTrustDomainFromString("example.org"))
	for _, a := range authorities {
		b.AddX509Authority(a)
	}
	return x509bundle.NewSet(b)
}

func roles(links []Link) string {
	var r []string
	for _, l := range links {
		r = append(r, string(l.Role))
	}
	return strings.Join(r, ",")
}

func TestResolve_VerifiedThreeLevelChain(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "intermediate", root)
	leaf, key := newLeaf(t, testID, inter)
	stale := newCA(t, "stale root", nil)

	res := Resolve(svidFor(t, []*x509.Certificate{leaf, inter.cert}, key), bundleOf(t, stale.cert, root.cert))

	if !res.Verified || res.Err != nil {
		t.Fatalf("expected verified chain, got err %v", res.Err)
	}
	if got := roles(res.Links); got != "leaf,intermediate,root" {
		t.Errorf("roles = %s", got)
	}
	if !res.Links[2].FromBundle || !res.Links[2].Cert.Equal(root.cert) {
		t.Error("last link should be the bundle root that signed the intermediate")
	}
	if !res.AnchorsOf(root.cert) {
		t.Error("root should anchor the SVID")
	}
	if res.AnchorsOf(stale.cert) {
		t.Error("stale root must not be reported as anchoring the SVID")
	}
}

func TestResolve_UnverifiedMatchesRootByKeyID(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "intermediate", root)
	leaf, key := newLeaf(t, testID, inter)

	// Only the leaf is sent, so verification cannot build a path to the root.
	res := Resolve(svidFor(t, []*x509.Certificate{leaf}, key), bundleOf(t, root.cert))
	if res.Verified || res.Err == nil {
		t.Fatal("expected verification to fail without the intermediate")
	}
	if got := roles(res.Links); got != "leaf" {
		t.Errorf("roles = %s, want only the leaf (its AKI names the missing intermediate)", got)
	}

	// Leaf and intermediate sent, but the bundle holds a different root.
	other := newCA(t, "other root", nil)
	res = Resolve(svidFor(t, []*x509.Certificate{leaf, inter.cert}, key), bundleOf(t, other.cert))
	if res.Verified {
		t.Fatal("expected verification to fail against an unrelated root")
	}
	if got := roles(res.Links); got != "leaf,intermediate" {
		t.Errorf("roles = %s", got)
	}
}

func TestResolve_UnverifiedStillShowsMatchingRoot(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "intermediate", root)
	leaf, key := newLeaf(t, testID, inter)

	// A leaf with a CA flag fails SPIFFE leaf rules even though the path exists.
	leaf.IsCA = true
	res := Resolve(svidFor(t, []*x509.Certificate{leaf, inter.cert}, key), bundleOf(t, root.cert))
	if res.Verified {
		t.Fatal("expected SPIFFE leaf verification to fail")
	}
	if got := roles(res.Links); got != "leaf,intermediate,root" {
		t.Errorf("roles = %s, want the bundle root matched by key ID", got)
	}
}

func TestResolve_NoCertificates(t *testing.T) {
	if res := Resolve(&x509svid.SVID{}, nil); res.Err == nil {
		t.Error("expected an error for an SVID without certificates")
	}
}

func TestFormatKeyID(t *testing.T) {
	if got := FormatKeyID([]byte{0x0a, 0xff, 0x10}); got != "0A:FF:10" {
		t.Errorf("FormatKeyID = %q", got)
	}
	if got := FormatKeyID(nil); got != "" {
		t.Errorf("FormatKeyID(nil) = %q", got)
	}
}
