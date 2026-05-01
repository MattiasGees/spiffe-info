package server

import (
	"context"
	"fmt"
	"net/http"

	webpkg "github.com/mattiasGees/spiffe-info/web"
	"github.com/mattiasGees/spiffe-info/internal/workload"
)

type Server struct {
	cfg      serverConfig
	store    workload.Store
	httpSrv  *http.Server
}

type serverConfig struct {
	Port        int
	JWTAudience string
}

func New(port int, jwtAudience string, store workload.Store) *Server {
	s := &Server{
		cfg:   serverConfig{Port: port, JWTAudience: jwtAudience},
		store: store,
	}

	mux := http.NewServeMux()

	h := &handlers{store: store, jwtAudience: jwtAudience}
	mux.HandleFunc("GET /api/x509-svid", h.handleX509SVID)
	mux.HandleFunc("GET /api/jwt-svid", h.handleJWTSVID)
	mux.HandleFunc("GET /api/trust-bundles", h.handleTrustBundles)
	mux.Handle("/", http.FileServer(http.FS(webpkg.FS)))

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	return s
}

func (s *Server) ListenAndServe() error {
	return s.httpSrv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}
