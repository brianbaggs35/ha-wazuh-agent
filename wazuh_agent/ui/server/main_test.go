package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func serverEnv(public, static string) func(string) string {
	return env(map[string]string{
		"WAZUH_UI_LISTEN":       "127.0.0.1:0",
		"WAZUH_UI_ALLOW":        "127.0.0.1",
		"WAZUH_UI_PUBLIC_DIR":   public,
		"WAZUH_UI_STATIC_DIR":   static,
		"WAZUH_UI_UPDATE_CHECK": "false",
	})
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func get(t *testing.T, address, path string) (int, string) {
	t.Helper()
	response, err := http.Get("http://" + address + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func TestRunRefusesABadConfiguration(t *testing.T) {
	var logs bytes.Buffer
	code := run(context.Background(), env(map[string]string{"WAZUH_UI_ALLOW": "nonsense"}), &logs, nil)
	if code != 2 || !strings.Contains(logs.String(), "allow list") {
		t.Errorf("code=%d logs=%q", code, logs.String())
	}
}

func TestRunReportsAListenFailure(t *testing.T) {
	restore := listen
	defer func() { listen = restore }()
	listen = func(string, string) (net.Listener, error) { return nil, errors.New("address in use") }

	var logs bytes.Buffer
	if code := run(context.Background(), serverEnv(t.TempDir(), t.TempDir()), &logs, nil); code != 1 || !strings.Contains(logs.String(), "address in use") {
		t.Errorf("code=%d logs=%q", code, logs.String())
	}
}

func TestRunServesThePageAndStopsCleanly(t *testing.T) {
	public, static := t.TempDir(), t.TempDir()
	writeFiles(t, public, map[string]string{"daemons.txt": daemonsRunning, "expected.txt": expectedAll, "agentd.state": stateConnected})
	writeFiles(t, static, map[string]string{"index.html": "<h1>Wazuh Agent</h1>"})

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan net.Addr, 1)
	done := make(chan int, 1)
	go func() { done <- run(ctx, serverEnv(public, static), io.Discard, ready) }()
	address := (<-ready).String()

	if code, body := get(t, address, "/"); code != 200 || !strings.Contains(body, "Wazuh Agent") {
		t.Errorf("page: %d %q", code, body)
	}
	if code, body := get(t, address, "/api/status"); code != 200 || !strings.Contains(body, `"state":"running"`) {
		t.Errorf("status: %d %q", code, body)
	}

	cancel()
	if code := <-done; code != 0 {
		t.Errorf("a clean stop must exit 0, got %d", code)
	}
}

// brokenListener accepts nothing: Serve fails straight away, as when the socket is torn down.
type brokenListener struct{ net.Listener }

func (brokenListener) Accept() (net.Conn, error) { return nil, errors.New("listener broke") }

func TestRunReportsAServerFailure(t *testing.T) {
	restore := listen
	defer func() { listen = restore }()
	listen = func(network, address string) (net.Listener, error) {
		inner, err := net.Listen(network, address)
		return brokenListener{inner}, err
	}

	var logs bytes.Buffer
	if code := run(context.Background(), serverEnv(t.TempDir(), t.TempDir()), &logs, nil); code != 1 || !strings.Contains(logs.String(), "listener broke") {
		t.Errorf("code=%d logs=%q", code, logs.String())
	}
}

func TestRunReportsAShutdownThatCannotFinish(t *testing.T) {
	restore := shutdownTimeout
	defer func() { shutdownTimeout = restore }()
	shutdownTimeout = 100 * time.Millisecond

	// A request that cannot finish: its status file is a pipe nobody writes to.
	public := t.TempDir()
	fifo := filepath.Join(public, "daemons.txt")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("cannot create a pipe here:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan net.Addr, 1)
	done := make(chan int, 1)
	var logs bytes.Buffer
	go func() { done <- run(ctx, serverEnv(public, t.TempDir()), &logs, ready) }()
	address := (<-ready).String()

	go func() { _, _ = http.Get("http://" + address + "/api/status") }()
	time.Sleep(300 * time.Millisecond) // let the request reach the handler and block on the pipe

	cancel()
	if code := <-done; code != 1 || !strings.Contains(logs.String(), "deadline") {
		t.Errorf("code=%d logs=%q", code, logs.String())
	}

	// Let the blocked request finish so nothing is left hanging.
	writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err == nil {
		_ = writer.Close()
	}
}

func TestMain(t *testing.T) {
	restore := exit
	defer func() { exit = restore }()
	var got int
	exit = func(code int) { got = code }

	t.Setenv("WAZUH_UI_ALLOW", "nonsense") // makes run return at once, with code 2
	main()
	if got != 2 {
		t.Errorf("main passed %d to exit, want 2", got)
	}
}
