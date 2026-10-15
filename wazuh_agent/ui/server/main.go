// Command wazuh-ha-ui is the read-only status page of the Wazuh Agent Home Assistant app.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// Seams for the tests: the real values are what runs in the app.
var (
	exit            = os.Exit
	listen          = net.Listen
	shutdownTimeout = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	exit(run(ctx, os.Getenv, os.Stderr, nil))
}

// run starts the server and blocks until ctx ends or the server fails. ready, if not nil,
// receives the address the server listens on (tests use it to find the port).
func run(ctx context.Context, getenv func(string) string, logs io.Writer, ready chan<- net.Addr) int {
	cfg, err := LoadConfig(getenv)
	if err != nil {
		fmt.Fprintln(logs, "wazuh-ha-ui:", err)
		return 2
	}

	server := &Server{
		Config:  cfg,
		Public:  os.DirFS(cfg.PublicDir),
		Static:  os.DirFS(cfg.StaticDir),
		Updates: NewUpdateChecker(runtime.GOARCH, cfg.SupervisorToken, cfg.UpdateCheck),
		Dialer:  &net.Dialer{},
	}

	listener, err := listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintln(logs, "wazuh-ha-ui:", err)
		return 1
	}
	if ready != nil {
		ready <- listener.Addr()
	}

	httpServer := &http.Server{
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	failed := make(chan error, 1)
	go func() { failed <- httpServer.Serve(listener) }()

	select {
	case err := <-failed:
		fmt.Fprintln(logs, "wazuh-ha-ui:", err)
		return 1
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil {
			fmt.Fprintln(logs, "wazuh-ha-ui:", err)
			return 1
		}
		return 0
	}
}
