// Package chain resolves the certificate chain of an X.509-SVID: the leaf and
// intermediates the Workload API delivered, plus the trust bundle root that
// anchors them.
package chain

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Role is the position of a certificate in the chain.
type Role string

const (
	RoleLeaf         Role = "leaf"
	RoleIntermediate Role = "intermediate"
	RoleRoot         Role = "root"
)

// Link is one certificate in the chain, ordered leaf first.
type Link struct {
	Cert *x509.Certificate
	Role Role
	// FromBundle is true for the root taken from the trust bundle rather than
	// from the certificates the Workload API sent with the SVID.
	FromBundle bool
}

// Result is the resolved chain.
type Result struct {
	Links []Link
	// Verified is true when the SVID verifies against the trust bundle of its
	// trust domain. When false, Err says why and Links holds what the Workload
	// API sent, plus a bundle root matched by key ID if one exists.
	Verified bool
	Err      error
}

// Resolve verifies svid against bundles and returns the chain leaf first.
func Resolve(svid *x509svid.SVID, bundles x509bundle.Source) Result {
	if svid == nil || len(svid.Certificates) == 0 {
		return Result{Err: fmt.Errorf("SVID has no certificates")}
	}
	if bundles != nil {
		_, chains, err := x509svid.Verify(svid.Certificates, bundles)
		if err == nil && len(chains) > 0 {
			return Result{Links: linksFromVerified(chains[0]), Verified: true}
		}
		if err != nil {
			return Result{Links: unverifiedLinks(svid, bundles), Err: err}
		}
	}
	return Result{Links: unverifiedLinks(svid, nil), Err: fmt.Errorf("no trust bundle available")}
}

// AnchorsOf reports whether cert is the root that anchors the chain.
func (r Result) AnchorsOf(cert *x509.Certificate) bool {
	for _, l := range r.Links {
		if l.FromBundle && l.Cert.Equal(cert) {
			return true
		}
	}
	return false
}

// FormatKeyID renders a key identifier as colon-separated uppercase hex.
func FormatKeyID(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	parts := make([]string, len(id))
	for i, b := range id {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// linksFromVerified labels a verified chain. The last certificate is the trust
// bundle authority that x509.Verify terminated on.
func linksFromVerified(certs []*x509.Certificate) []Link {
	links := make([]Link, len(certs))
	for i, c := range certs {
		links[i] = Link{Cert: c, Role: roleAt(i, len(certs))}
	}
	links[len(links)-1].FromBundle = true
	return links
}

// unverifiedLinks returns what the Workload API sent and, when the last
// certificate's Authority Key ID matches a bundle authority, that authority as
// the probable root. This keeps the chain readable when verification fails,
// which is exactly when it is most useful to see.
func unverifiedLinks(svid *x509svid.SVID, bundles x509bundle.Source) []Link {
	certs := svid.Certificates
	var root *x509.Certificate
	last := certs[len(certs)-1]
	if bundles != nil && len(last.AuthorityKeyId) > 0 {
		if b, err := bundles.GetX509BundleForTrustDomain(svid.ID.TrustDomain()); err == nil {
			for _, a := range b.X509Authorities() {
				if bytes.Equal(a.SubjectKeyId, last.AuthorityKeyId) {
					root = a
					break
				}
			}
		}
	}
	links := make([]Link, 0, len(certs)+1)
	for i, c := range certs {
		// Without a verified path, only a self-signed CA is known to be a root.
		role := RoleIntermediate
		switch {
		case i == 0:
			role = RoleLeaf
		case c.IsCA && bytes.Equal(c.RawSubject, c.RawIssuer):
			role = RoleRoot
		}
		links = append(links, Link{Cert: c, Role: role})
	}
	if root != nil {
		links = append(links, Link{Cert: root, Role: RoleRoot, FromBundle: true})
	}
	return links
}

func roleAt(i, n int) Role {
	switch {
	case i == 0:
		return RoleLeaf
	case i == n-1:
		return RoleRoot
	default:
		return RoleIntermediate
	}
}
