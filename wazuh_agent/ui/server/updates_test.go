package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const packagesIndex = `Package: wazuh-manager
Version: 4.99.0-1

Package: wazuh-agent
Version: 4.14.9-1

Package: wazuh-agent
Version: 4.14.10-1

Package: wazuh-agent
Version: 4.9.2-1

Package: wazuh-agent
Version: not-a-version
`

func gz(t *testing.T, text string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// upstream serves the package index and the Supervisor's app info, and counts the requests.
func upstream(t *testing.T, packages func(http.ResponseWriter), app func(http.ResponseWriter, *http.Request)) (*UpdateChecker, *atomic.Int32, *clock) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/packages", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		packages(w)
	})
	mux.HandleFunc("/addons/self/info", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		app(w, r)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	tick := &clock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	return &UpdateChecker{
		Client: server.Client(), PackagesURL: server.URL + "/packages", SupervisorURL: server.URL,
		Token: "t0ken", Enabled: true, Now: tick.Now,
	}, &hits, tick
}

func goodPackages(t *testing.T) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = w.Write(gz(t, packagesIndex)) }
}

func goodApp(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer t0ken" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	_, _ = w.Write([]byte(`{"result":"ok","data":{"version":"1.0.0","version_latest":"1.1.0","update_available":true}}`))
}

func TestInfoReportsAnAgentAndAnAppUpdate(t *testing.T) {
	checker, _, _ := upstream(t, goodPackages(t), goodApp)
	info := checker.Info(context.Background(), "4.14.9", false)
	if !info.Enabled || info.Agent.Latest != "4.14.10" || !info.Agent.Available || info.Agent.Installed != "4.14.9" {
		t.Errorf("agent: %+v", info.Agent)
	}
	if !info.App.Available || info.App.Version != "1.0.0" || info.App.Latest != "1.1.0" {
		t.Errorf("app: %+v", info.App)
	}
	if info.CheckedAt != "2026-10-15T12:00:00Z" {
		t.Errorf("checked_at: %q", info.CheckedAt)
	}
}

func TestInfoWhenCurrent(t *testing.T) {
	checker, _, _ := upstream(t, goodPackages(t), goodApp)
	if info := checker.Info(context.Background(), "4.14.10", false); info.Agent.Available {
		t.Errorf("4.14.10 is the newest: %+v", info.Agent)
	}
}

func TestInfoDisabled(t *testing.T) {
	checker, hits, _ := upstream(t, goodPackages(t), goodApp)
	checker.Enabled = false
	info := checker.Info(context.Background(), "4.14.9", false)
	if info.Enabled || info.Agent.Installed != "4.14.9" || hits.Load() != 0 {
		t.Errorf("a disabled check must not ask anyone: %+v hits=%d", info, hits.Load())
	}
}

func TestInfoWithoutASupervisorTokenSkipsTheAppCheck(t *testing.T) {
	checker, hits, _ := upstream(t, goodPackages(t), goodApp)
	checker.Token = ""
	info := checker.Info(context.Background(), "4.14.9", false)
	if info.App != (AppUpdate{}) || hits.Load() != 1 {
		t.Errorf("app=%+v hits=%d", info.App, hits.Load())
	}
}

func TestInfoIsCachedAndRefreshIsThrottled(t *testing.T) {
	checker, hits, tick := upstream(t, goodPackages(t), goodApp)
	ctx := context.Background()
	checker.Info(ctx, "4.14.9", false)
	checker.Info(ctx, "4.14.9", false)
	if hits.Load() != 2 { // one package index + one app lookup, once
		t.Fatalf("the second call should come from the cache, hits=%d", hits.Load())
	}

	tick.now = tick.now.Add(10 * time.Second)
	checker.Info(ctx, "4.14.9", true)
	if hits.Load() != 2 {
		t.Errorf("a refresh within a minute must be ignored, hits=%d", hits.Load())
	}

	tick.now = tick.now.Add(time.Minute)
	checker.Info(ctx, "4.14.9", true)
	if hits.Load() != 4 {
		t.Errorf("a refresh after a minute must ask again, hits=%d", hits.Load())
	}
}

func TestInfoExpiresAndFollowsTheInstalledVersion(t *testing.T) {
	checker, hits, tick := upstream(t, goodPackages(t), goodApp)
	ctx := context.Background()
	checker.Info(ctx, "4.14.9", false)

	checker.Info(ctx, "4.14.10", false) // a different installed version: the cached answer is not for it
	if hits.Load() != 4 {
		t.Errorf("hits=%d", hits.Load())
	}

	tick.now = tick.now.Add(updateTTL + time.Second)
	checker.Info(ctx, "4.14.10", false)
	if hits.Load() != 6 {
		t.Errorf("an expired answer must be refreshed, hits=%d", hits.Load())
	}
}

func TestInfoReportsWhatWentWrongWithoutFailing(t *testing.T) {
	cases := []struct {
		name     string
		packages func(http.ResponseWriter)
		want     string
	}{
		{"an error status", func(w http.ResponseWriter) { http.Error(w, "down", http.StatusBadGateway) }, "answered 502"},
		{"a body that is not gzip", func(w http.ResponseWriter) { _, _ = w.Write([]byte("plain text")) }, "not readable"},
		{"a truncated gzip body", func(w http.ResponseWriter) {
			data := gz(t, strings.Repeat("Package: x\n\n", 1000))
			_, _ = w.Write(data[:len(data)/2])
		}, "not readable"},
		{"an index without the agent", func(w http.ResponseWriter) { _, _ = w.Write(gz(t, "Package: other\nVersion: 1.0.0-1\n")) }, "no wazuh-agent version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checker, _, _ := upstream(t, c.packages, goodApp)
			info := checker.Info(context.Background(), "4.14.9", false)
			if !strings.Contains(info.Agent.Error, c.want) || info.Agent.Latest != "" || info.Agent.Available {
				t.Errorf("want an error containing %q, got %+v", c.want, info.Agent)
			}
		})
	}
}

func TestInfoWhenWazuhIsUnreachableOrTheURLIsBad(t *testing.T) {
	checker, _, _ := upstream(t, goodPackages(t), goodApp)
	checker.PackagesURL = "http://127.0.0.1:1/unreachable"
	if info := checker.Info(context.Background(), "4.14.9", false); !strings.Contains(info.Agent.Error, "could not reach") {
		t.Errorf("got %+v", info.Agent)
	}

	checker, _, _ = upstream(t, goodPackages(t), goodApp)
	checker.PackagesURL = "http://bad\x7furl"
	if info := checker.Info(context.Background(), "4.14.9", false); !strings.Contains(info.Agent.Error, "could not check") {
		t.Errorf("got %+v", info.Agent)
	}
}

func TestAppUpdateFailures(t *testing.T) {
	cases := []struct {
		name string
		app  func(http.ResponseWriter, *http.Request)
		want string
	}{
		{"a refusal", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusForbidden) }, "answered 403"},
		{"an unreadable answer", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{broken")) }, "not understood"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checker, _, _ := upstream(t, goodPackages(t), c.app)
			info := checker.Info(context.Background(), "4.14.9", false)
			if !strings.Contains(info.App.Error, c.want) {
				t.Errorf("got %+v", info.App)
			}
		})
	}

	checker, _, _ := upstream(t, goodPackages(t), goodApp)
	checker.SupervisorURL = "http://127.0.0.1:1"
	if info := checker.Info(context.Background(), "4.14.9", false); !strings.Contains(info.App.Error, "could not ask") {
		t.Errorf("got %+v", info.App)
	}
	checker, _, _ = upstream(t, goodPackages(t), goodApp)
	checker.SupervisorURL = "http://bad\x7furl"
	if info := checker.Info(context.Background(), "4.14.9", false); info.App.Error == "" {
		t.Errorf("a bad URL must be reported: %+v", info.App)
	}
}

func TestNewestAgentComparesNumbersNotText(t *testing.T) {
	got, err := NewestAgent(packagesIndex)
	if err != nil || got != "4.14.10" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := NewestAgent(""); err == nil {
		t.Error("an empty index has no agent")
	}
}

func TestVersionComparison(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.14.10-1", "4.14.9-1", 1},
		{"4.14.9-1", "4.14.10-1", -1},
		{"4.14.9-1", "4.14.9-1", 0},
		{"4.14.9-2", "4.14.9-1", 1},
		{"4.14.9", "4.14.9-1", -1}, // a plain version has no package revision
		{"4.15.0", "4.14.9", 1},
		{"garbage", "4.14.9", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if !newerVersion("4.14.10", "4.14.9") || newerVersion("4.14.9", "4.14.9") {
		t.Error("newerVersion is wrong")
	}
}

func TestNewUpdateChecker(t *testing.T) {
	checker := NewUpdateChecker("arm64", "token", true)
	if !strings.HasSuffix(checker.PackagesURL, "/binary-arm64/Packages.gz") || !strings.HasPrefix(checker.PackagesURL, "https://") {
		t.Errorf("the update source must be Wazuh's HTTPS repository for this architecture: %s", checker.PackagesURL)
	}
	if checker.SupervisorURL != "http://supervisor" || checker.Now == nil || checker.Client.Timeout == 0 {
		t.Errorf("%+v", checker)
	}
}
