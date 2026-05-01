package workload

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Store is the read interface used by the HTTP handlers and printer.
// It is satisfied by Watcher and can be mocked in tests.
type Store interface {
	CurrentX509Context() *workloadapi.X509Context
	FetchJWTSVID(ctx context.Context, audience string) (*jwtsvid.SVID, error)
}

// Watcher subscribes to X.509 context updates from the Workload API,
// caches the latest context, and invokes onUpdate on each rotation.
type Watcher struct {
	client   *workloadapi.Client
	mu       sync.RWMutex
	current  *workloadapi.X509Context
	onUpdate func(*workloadapi.X509Context)
}

func NewWatcher(client *workloadapi.Client, onUpdate func(*workloadapi.X509Context)) *Watcher {
	return &Watcher{
		client:   client,
		onUpdate: onUpdate,
	}
}

// Watch blocks until ctx is cancelled, calling the Workload API's
// streaming X.509 watch with automatic retries.
func (w *Watcher) Watch(ctx context.Context) error {
	return w.client.WatchX509Context(ctx, w)
}

func (w *Watcher) OnX509ContextUpdate(ctx *workloadapi.X509Context) {
	w.mu.Lock()
	w.current = ctx
	w.mu.Unlock()
	if w.onUpdate != nil {
		w.onUpdate(ctx)
	}
}

func (w *Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) == codes.Canceled {
		return
	}
	fmt.Fprintf(os.Stderr, "workload API watcher error: %v\n", err)
}

func (w *Watcher) CurrentX509Context() *workloadapi.X509Context {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}

func (w *Watcher) FetchJWTSVID(ctx context.Context, audience string) (*jwtsvid.SVID, error) {
	return w.client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
}
