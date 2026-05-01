package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// WorkloadAPIServer implements the SPIFFE Workload API gRPC service.
type WorkloadAPIServer struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer

	mu          sync.RWMutex
	spiffeID    string
	trustDomain string
	currentSVID *IssuedSVID
	jwtIssuer   *JWTIssuer
	jwtTTL      time.Duration

	pubsub pubSub
}

// NewWorkloadAPIServer creates a server and issues the first SVID.
func NewWorkloadAPIServer(ca *CA, jwtIssuer *JWTIssuer, spiffeID, trustDomain string, svidTTL, jwtTTL time.Duration) (*WorkloadAPIServer, error) {
	svid, err := ca.Issue(spiffeID, svidTTL)
	if err != nil {
		return nil, fmt.Errorf("issuing initial SVID: %w", err)
	}
	s := &WorkloadAPIServer{
		spiffeID:    spiffeID,
		trustDomain: trustDomain,
		currentSVID: svid,
		jwtIssuer:   jwtIssuer,
		jwtTTL:      jwtTTL,
	}
	return s, nil
}

// Rotate re-issues the SVID and notifies all active streams.
func (s *WorkloadAPIServer) Rotate(ca *CA, ttl time.Duration) error {
	svid, err := ca.Issue(s.spiffeID, ttl)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.currentSVID = svid
	s.mu.Unlock()
	s.pubsub.publish()
	return nil
}

// FetchX509SVID streams X.509-SVID updates to the client.
func (s *WorkloadAPIServer) FetchX509SVID(req *workloadpb.X509SVIDRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}

	if err := stream.Send(s.buildX509Response()); err != nil {
		return err
	}

	ch, unsub := s.pubsub.subscribe()
	defer unsub()

	for {
		select {
		case <-ch:
			if err := stream.Send(s.buildX509Response()); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// FetchX509Bundles streams trust bundle updates.
func (s *WorkloadAPIServer) FetchX509Bundles(req *workloadpb.X509BundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}

	if err := stream.Send(s.buildX509BundlesResponse()); err != nil {
		return err
	}

	ch, unsub := s.pubsub.subscribe()
	defer unsub()

	for {
		select {
		case <-ch:
			if err := stream.Send(s.buildX509BundlesResponse()); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// FetchJWTSVID issues a JWT-SVID on demand (unary RPC).
func (s *WorkloadAPIServer) FetchJWTSVID(ctx context.Context, req *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	if err := checkHeader(ctx); err != nil {
		return nil, err
	}
	if len(req.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}

	token, err := s.jwtIssuer.Issue(s.spiffeID, req.Audience, s.jwtTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing JWT: %v", err)
	}

	return &workloadpb.JWTSVIDResponse{
		Svids: []*workloadpb.JWTSVID{
			{SpiffeId: s.spiffeID, Svid: token, Hint: "spiffe-info-mock"},
		},
	}, nil
}

// FetchJWTBundles streams the JWKS for the trust domain.
func (s *WorkloadAPIServer) FetchJWTBundles(req *workloadpb.JWTBundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}

	resp, err := s.buildJWTBundlesResponse()
	if err != nil {
		return status.Errorf(codes.Internal, "building JWKS: %v", err)
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	<-stream.Context().Done()
	return nil
}

// ── Builders ─────────────────────────────────────────────────────────────────

func (s *WorkloadAPIServer) buildX509Response() *workloadpb.X509SVIDResponse {
	s.mu.RLock()
	svid := s.currentSVID
	s.mu.RUnlock()

	return &workloadpb.X509SVIDResponse{
		Svids: []*workloadpb.X509SVID{
			{
				SpiffeId:    s.spiffeID,
				X509Svid:    svid.CertDER,
				X509SvidKey: svid.KeyDER,
				Bundle:      svid.BundleDER,
				Hint:        "spiffe-info-mock",
			},
		},
	}
}

func (s *WorkloadAPIServer) buildX509BundlesResponse() *workloadpb.X509BundlesResponse {
	s.mu.RLock()
	svid := s.currentSVID
	s.mu.RUnlock()

	return &workloadpb.X509BundlesResponse{
		Bundles: map[string][]byte{
			s.trustDomain: svid.BundleDER,
		},
	}
}

func (s *WorkloadAPIServer) buildJWTBundlesResponse() (*workloadpb.JWTBundlesResponse, error) {
	jwks, err := s.jwtIssuer.JWKSBytes()
	if err != nil {
		return nil, err
	}
	return &workloadpb.JWTBundlesResponse{
		Bundles: map[string][]byte{
			s.trustDomain: jwks,
		},
	}, nil
}

// ── Header check ─────────────────────────────────────────────────────────────

func checkHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.InvalidArgument, "missing metadata")
	}
	vals := md.Get("workload.spiffe.io")
	if len(vals) == 0 || vals[0] != "true" {
		return status.Error(codes.InvalidArgument, "missing workload.spiffe.io header")
	}
	return nil
}

// ── pubSub ────────────────────────────────────────────────────────────────────

type pubSub struct {
	mu   sync.Mutex
	subs []chan struct{}
}

func (p *pubSub) subscribe() (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	p.mu.Lock()
	p.subs = append(p.subs, ch)
	p.mu.Unlock()

	return ch, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for i, s := range p.subs {
			if s == ch {
				p.subs = append(p.subs[:i], p.subs[i+1:]...)
				return
			}
		}
	}
}

func (p *pubSub) publish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ch := range p.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
