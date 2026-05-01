package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mockinternal "github.com/mattiasGees/spiffe-info/cmd/mock-workload-api/internal"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

func main() {
	var (
		socketPath       = flag.String("socket", "/tmp/spiffe-info-mock.sock", "Unix socket path to listen on")
		spiffeID         = flag.String("spiffe-id", "spiffe://example.org/workload/mock", "SPIFFE ID to issue in SVIDs")
		rotationInterval = flag.Duration("rotation-interval", 60*time.Second, "How often to rotate the X.509-SVID")
		svidTTL          = flag.Duration("ttl", time.Hour, "Certificate TTL")
		jwtTTL           = flag.Duration("jwt-ttl", time.Hour, "JWT-SVID TTL")
	)
	flag.Parse()

	trustDomain := extractTrustDomain(*spiffeID)
	issuerURI := "spiffe://" + trustDomain

	fmt.Printf("spiffe-info mock workload API\n")
	fmt.Printf("  SPIFFE ID         : %s\n", *spiffeID)
	fmt.Printf("  Trust domain      : %s\n", trustDomain)
	fmt.Printf("  Socket            : %s\n", *socketPath)
	fmt.Printf("  SVID TTL          : %s\n", *svidTTL)
	fmt.Printf("  Rotation interval : %s\n", *rotationInterval)
	fmt.Println()

	// Generate CA valid for 10× the SVID TTL (or at least 24h)
	caTTL := *svidTTL * 10
	if caTTL < 24*time.Hour {
		caTTL = 24 * time.Hour
	}
	ca, err := mockinternal.NewCA(caTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate CA: %v\n", err)
		os.Exit(1)
	}

	jwtIssuer, err := mockinternal.NewJWTIssuer(issuerURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create JWT issuer: %v\n", err)
		os.Exit(1)
	}

	srv, err := mockinternal.NewWorkloadAPIServer(ca, jwtIssuer, *spiffeID, trustDomain, *svidTTL, *jwtTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create workload API server: %v\n", err)
		os.Exit(1)
	}

	// Remove stale socket file
	os.Remove(*socketPath)
	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer os.Remove(*socketPath)

	grpcSrv := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(grpcSrv, srv)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Rotation goroutine
	go func() {
		ticker := time.NewTicker(*rotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Printf("[%s] rotating X.509-SVID\n", time.Now().UTC().Format("15:04:05"))
				if err := srv.Rotate(ca, *svidTTL); err != nil {
					fmt.Fprintf(os.Stderr, "rotation error: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Shutdown goroutine
	go func() {
		<-ctx.Done()
		fmt.Println("\nshutting down mock workload API")
		grpcSrv.GracefulStop()
	}()

	fmt.Printf("listening on unix://%s\n", *socketPath)
	fmt.Printf("set SPIFFE_ENDPOINT_SOCKET=unix://%s\n", *socketPath)
	if err := grpcSrv.Serve(lis); err != nil {
		fmt.Fprintf(os.Stderr, "gRPC server error: %v\n", err)
		os.Exit(1)
	}
}

func extractTrustDomain(spiffeID string) string {
	s := strings.TrimPrefix(spiffeID, "spiffe://")
	if idx := strings.Index(s, "/"); idx >= 0 {
		return s[:idx]
	}
	return s
}
