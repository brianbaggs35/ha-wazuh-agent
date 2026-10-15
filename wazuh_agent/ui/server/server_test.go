package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func testServer(t *testing.T, public fs.FS) *Server {
	t.Helper()
	allow, err := ParseAllowList("192.0.2.0/24, ::1")
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Config:  Config{Allow: allow},
		Public:  public,
		Static:  fstest.MapFS{"index.html": {Data: []byte("<h1>page</h1>")}, "assets/app.js": {Data: []byte("console.log(1)")}, "assets/sub/x.js": {Data: []byte("x")}},
		Updates: &UpdateChecker{Enabled: false},
		Dialer:  &fakeDialer{},
		Now:     func() time.Time { return epoch },
	}
}

func do(handler http.Handler, method, target, remote string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	request.RemoteAddr = remote
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

const gateway = "192.0.2.10:50000"

func TestOnlyTheAllowedNetworksAreServed(t *testing.T) {
	handler := testServer(t, files(true, nil)).Handler()
	cases := []struct {
		remote string
		want   int
	}{
		{gateway, http.StatusOK},
		{"[::1]:5000", http.StatusOK},
		{"198.51.100.1:5000", http.StatusForbidden},
		{"no-port", http.StatusForbidden},
		{"example.com:80", http.StatusForbidden},
	}
	for _, c := range cases {
		if got := do(handler, "GET", "/api/status", c.remote).Code; got != c.want {
			t.Errorf("%s: got %d want %d", c.remote, got, c.want)
		}
	}
}

func TestAForwardedHeaderCannotTalkItsWayIn(t *testing.T) {
	handler := testServer(t, files(true, nil)).Handler()
	request := httptest.NewRequest("GET", "/api/status", nil)
	request.RemoteAddr = "198.51.100.1:5000"
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	request.Header.Set("X-Real-IP", "192.0.2.10")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("got %d", recorder.Code)
	}
}

func TestSecurityHeadersAreOnEveryAllowedResponse(t *testing.T) {
	handler := testServer(t, files(true, nil)).Handler()
	for _, path := range []string{"/", "/api/status", "/missing"} {
		header := do(handler, "GET", path, gateway).Header()
		for _, name := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Resource-Policy"} {
			if header.Get(name) == "" {
				t.Errorf("%s: missing %s", path, name)
			}
		}
		if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src 'self' 'unsafe") {
			t.Errorf("%s: the CSP must deny by default and allow no inline script: %s", path, csp)
		}
	}
}

func TestStatusEndpoint(t *testing.T) {
	recorder := do(testServer(t, files(true, nil)).Handler(), "GET", "/api/status", gateway)
	if recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", recorder.Header())
	}
	var status Status
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "running" {
		t.Errorf("state %q", status.State)
	}
}

func TestStatusUsesTheRealClockWhenNoneIsInjected(t *testing.T) {
	public := files(true, nil)
	public["daemons.txt"] = &fstest.MapFile{Data: []byte(daemonsRunning), ModTime: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
	server := testServer(t, public)
	server.Now = nil // the real clock: a status file from the year 2000 is stale whatever today is
	var status Status
	_ = json.Unmarshal(do(server.Handler(), "GET", "/api/status", gateway).Body.Bytes(), &status)
	if status.State != "stale" {
		t.Errorf("got %q", status.State)
	}
}

func TestUpdatesEndpointUsesTheInstalledVersion(t *testing.T) {
	server := testServer(t, files(true, nil))
	var body UpdateInfo
	_ = json.Unmarshal(do(server.Handler(), "GET", "/api/updates?refresh=1", gateway).Body.Bytes(), &body)
	if body.Enabled || body.Agent.Installed != "4.14.9" {
		t.Errorf("got %+v", body)
	}

	_ = json.Unmarshal(do(testServer(t, fstest.MapFS{}).Handler(), "GET", "/api/updates", gateway).Body.Bytes(), &body)
	if body.Agent.Installed != "" {
		t.Errorf("without a summary there is no installed version: %+v", body)
	}
}

func TestLogsEndpoint(t *testing.T) {
	server := testServer(t, files(true, map[string]string{"log.txt": "first\nsecond\n"}))
	var body map[string][]string
	_ = json.Unmarshal(do(server.Handler(), "GET", "/api/logs", gateway).Body.Bytes(), &body)
	if len(body["lines"]) != 2 || body["lines"][1] != "second" {
		t.Errorf("got %v", body)
	}

	body = nil
	_ = json.Unmarshal(do(testServer(t, fstest.MapFS{}).Handler(), "GET", "/api/logs", gateway).Body.Bytes(), &body)
	if body["lines"] == nil || len(body["lines"]) != 0 {
		t.Errorf("a missing log is an empty list, not null: %v", body)
	}
}

func TestConnectionTestEndpoint(t *testing.T) {
	var body struct{ Results []ConnectionResult }
	_ = json.Unmarshal(do(testServer(t, files(true, nil)).Handler(), "GET", "/api/connection-test", gateway).Body.Bytes(), &body)
	if len(body.Results) != 2 || !body.Results[0].Reachable {
		t.Errorf("got %+v", body.Results)
	}

	recorder := do(testServer(t, fstest.MapFS{}).Handler(), "GET", "/api/connection-test", gateway)
	if !strings.Contains(recorder.Body.String(), `"results":[]`) {
		t.Errorf("without a summary the list is empty: %s", recorder.Body.String())
	}
}

func TestTheServerIsReadOnly(t *testing.T) {
	handler := testServer(t, files(true, nil)).Handler()
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		for _, path := range []string{"/api/status", "/api/updates", "/", "/api/connection-test"} {
			if got := do(handler, method, path, gateway).Code; got != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got %d, want 405", method, path, got)
			}
		}
	}
}

func TestStaticFiles(t *testing.T) {
	handler := testServer(t, files(true, nil)).Handler()
	cases := []struct {
		target string
		want   int
		body   string
	}{
		{"/", 200, "<h1>page</h1>"},
		{"/assets/app.js", 200, "console.log(1)"},
		{"/assets/", 404, ""},
		{"/assets/sub/", 404, ""},
		{"/missing.js", 404, ""},
		{"/etc/passwd", 404, ""},
	}
	for _, c := range cases {
		recorder := do(handler, "GET", c.target, gateway)
		if recorder.Code != c.want || (c.body != "" && !strings.Contains(recorder.Body.String(), c.body)) {
			t.Errorf("%s: got %d %q", c.target, recorder.Code, recorder.Body.String())
		}
	}
	// A traversal attempt is redirected to the cleaned path, which does not exist: no file is read.
	recorder := do(handler, "GET", "/../../etc/passwd", gateway)
	if recorder.Code != http.StatusTemporaryRedirect || recorder.Header().Get("Location") != "/etc/passwd" || strings.Contains(recorder.Body.String(), "root:") {
		t.Errorf("traversal: %d %q", recorder.Code, recorder.Header().Get("Location"))
	}
	if recorder := do(handler, "HEAD", "/", gateway); recorder.Code != 200 || recorder.Body.Len() != 0 {
		t.Errorf("HEAD: %d %q", recorder.Code, recorder.Body.String())
	}
}

// brokenStat opens fine but cannot be stat'ed.
type brokenStat struct{ fstest.MapFS }

type brokenFile struct{ fs.File }

func (brokenFile) Stat() (fs.FileInfo, error) { return nil, errors.New("stat failed") }

func (b brokenStat) Open(name string) (fs.File, error) {
	file, err := b.MapFS.Open(name)
	if err != nil {
		return nil, err
	}
	return brokenFile{file}, nil
}

func TestNoListing(t *testing.T) {
	static := fstest.MapFS{"index.html": {Data: []byte("x")}, "dir/a.js": {Data: []byte("a")}, "withindex/index.html": {Data: []byte("i")}}
	listing := noListing{static}

	if _, err := listing.Open("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if file, err := listing.Open("dir/a.js"); err != nil {
		t.Errorf("a plain file must open: %v", err)
	} else {
		_ = file.Close()
	}
	if _, err := listing.Open("dir"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a directory without an index must not open: %v", err)
	}
	if file, err := listing.Open("withindex"); err != nil {
		t.Errorf("a directory with an index must open: %v", err)
	} else {
		_ = file.Close()
	}
	if _, err := (noListing{brokenStat{static}}).Open("index.html"); err == nil {
		t.Error("a file that cannot be stat'ed must not be served")
	}
}

func TestAllowedRejectsUnparseableAddresses(t *testing.T) {
	server := testServer(t, fstest.MapFS{})
	if server.allowed("") || server.allowed(net.JoinHostPort("not an ip", "1")) {
		t.Error("garbage must not be allowed")
	}
}
