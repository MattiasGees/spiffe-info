package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mattiasGees/spiffe-info/internal/config"
	"github.com/mattiasGees/spiffe-info/internal/printer"
	"github.com/mattiasGees/spiffe-info/internal/server"
	"github.com/mattiasGees/spiffe-info/internal/workload"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("spiffe-info starting\n")
	fmt.Printf("  workload API : %s\n", cfg.WorkloadAPIAddr)
	fmt.Printf("  HTTP port    : %d\n", cfg.Port)
	fmt.Printf("  JWT audience : %s\n", cfg.JWTAudience)
	fmt.Println()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(cfg.WorkloadAPIAddr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create workload API client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	watcher := workload.NewWatcher(client, func(ctx *workloadapi.X509Context) {
		printer.PrintX509Context(os.Stdout, ctx)
	})

	// Start X.509 watcher (push model — blocks until ctx cancelled)
	go func() {
		if err := watcher.Watch(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "watcher stopped: %v\n", err)
		}
	}()

	srv := server.New(cfg.Port, cfg.JWTAudience, watcher)

	go func() {
		fmt.Printf("web UI available at http://localhost:%d\n", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
		}
	}()

	<-ctx.Done()

	fmt.Println("\nshutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}
