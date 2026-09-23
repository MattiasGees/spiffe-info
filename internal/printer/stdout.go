package printer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mattiasGees/spiffe-info/internal/chain"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const divider = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

func PrintX509Context(w io.Writer, ctx *workloadapi.X509Context) {
	if len(ctx.SVIDs) == 0 {
		return
	}
	svid := ctx.SVIDs[0]
	if len(svid.Certificates) == 0 {
		return
	}
	printSVID(w, svid.ID.String(), svid.Hint, svid.Certificates[0], svid.PrivateKey)
	printChain(w, chain.Resolve(svid, ctx.Bundles))
}

// printChain draws the chain leaf first, one entry per certificate, then the
// verification result.
func printChain(w io.Writer, res chain.Result) {
	fmt.Fprintln(w, " Trust Chain")
	for i, l := range res.Links {
		branch, cont := "├─", "│ "
		if i == len(res.Links)-1 {
			branch, cont = "└─", "  "
		}
		name := l.Cert.Subject.String()
		if name == "" {
			name = "(empty subject)"
		}
		source := ""
		if l.FromBundle {
			source = "  [trust bundle]"
		}
		fmt.Fprintf(w, "  %s %-12s %s%s\n", branch, l.Role, name, source)
		fmt.Fprintf(w, "  %s              %s · expires %s (%s)\n", cont,
			keyAlgorithmName(l.Cert),
			l.Cert.NotAfter.UTC().Format("2006-01-02 15:04 UTC"),
			formatRemaining(l.Cert.NotAfter))
		if ski := chain.FormatKeyID(l.Cert.SubjectKeyId); ski != "" {
			fmt.Fprintf(w, "  %s              SKI %s\n", cont, ski)
		}
		if aki := chain.FormatKeyID(l.Cert.AuthorityKeyId); aki != "" && !l.FromBundle {
			fmt.Fprintf(w, "  %s              AKI %s\n", cont, aki)
		}
	}
	if res.Verified {
		fmt.Fprintln(w, "  ✓ Verified against the trust bundle")
	} else {
		fmt.Fprintf(w, "  ✗ Not verified: %v\n", res.Err)
	}
	fmt.Fprintln(w, divider)
}

func printSVID(w io.Writer, spiffeID, hint string, cert *x509.Certificate, key crypto.Signer) {
	now := time.Now().UTC()

	fmt.Fprintln(w, divider)
	fmt.Fprintf(w, " SPIFFE X.509-SVID Rotation — %s\n", now.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintln(w, divider)

	fmt.Fprintf(w, "  SPIFFE ID   : %s\n", spiffeID)
	if hint != "" {
		fmt.Fprintf(w, "  Hint        : %s\n", hint)
	}
	fmt.Fprintf(w, "  Subject     : %s\n", cert.Subject.String())
	fmt.Fprintf(w, "  Issuer      : %s\n", cert.Issuer.String())
	fmt.Fprintf(w, "  Serial No.  : %s\n", formatSerial(cert))
	fmt.Fprintf(w, "  Not Before  : %s\n", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "  Not After   : %s  (%s)\n",
		cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"),
		formatRemaining(cert.NotAfter))
	fmt.Fprintf(w, "  Key Algo    : %s\n", keyAlgorithmName(cert))
	fmt.Fprintf(w, "  Sig Algo    : %s\n", sigAlgorithmName(cert))
	fmt.Fprintln(w)

	pubKeyPEM, err := marshalPublicKey(key.Public())
	if err == nil {
		fmt.Fprintln(w, "  Public Key:")
		for _, line := range strings.Split(strings.TrimRight(pubKeyPEM, "\n"), "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	fmt.Fprintln(w, divider)
}

func formatSerial(cert *x509.Certificate) string {
	h := fmt.Sprintf("%X", cert.SerialNumber)
	if len(h)%2 != 0 {
		h = "0" + h
	}
	parts := make([]string, len(h)/2)
	for i := range parts {
		parts[i] = h[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

func formatRemaining(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		return "EXPIRED"
	}
	// Round to the nearest minute to avoid sub-second timing drift.
	total := int(d.Round(time.Minute).Minutes())
	days := total / (60 * 24)
	hours := (total % (60 * 24)) / 60
	mins := total % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm remaining", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm remaining", hours, mins)
	}
	return fmt.Sprintf("%dm remaining", mins)
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

func marshalPublicKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := pem.Encode(&sb, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
		return "", err
	}
	return sb.String(), nil
}
