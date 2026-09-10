package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

const (
	httpReadHeaderTimeout = 10 * time.Second
	httpReadTimeout       = 2 * time.Minute
	httpWriteTimeout      = 2 * time.Minute
	httpIdleTimeout       = 60 * time.Second
	httpShutdownTimeout   = 10 * time.Second
)

func runHTTP(ctx context.Context, cfg config.Config, server *mcp.Server) error {
	warnIfNonLoopbackHTTPBind(cfg.HTTPAddr)

	opts := &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        cfg.HTTPJSON,
		MaxRequestBodyBytes: cfg.HTTPMaxBodyBytes,
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, opts)

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	}
}

func warnIfNonLoopbackHTTPBind(addr string) {
	if config.IsLoopbackHTTPAddr(addr) {
		return
	}
	slog.Warn("http bind address is not loopback; this server has no authentication and is intended for local use only",
		"addr", addr,
		"guidance", "use stdio transport for Cursor/Claude Desktop; do not expose this endpoint on a network without your own access controls",
	)
}
