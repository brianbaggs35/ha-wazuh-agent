package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The sources are fixed in code on purpose: nothing configurable can redirect the update check to
// an address of someone's choosing.
const (
	packagesURLFormat = "https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-%s/Packages.gz"
	supervisorURL     = "http://supervisor"

	updateTTL       = 6 * time.Hour
	refreshThrottle = time.Minute
	maxIndexBytes   = 16 << 20
)

var versionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)-(\d+)$`)

// AgentUpdate compares the installed Wazuh agent with the newest stable one Wazuh publishes.
type AgentUpdate struct {
	Installed string `json:"installed"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// AppUpdate is what the Supervisor says about this app's own update.
type AppUpdate struct {
	Version   string `json:"version,omitempty"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// UpdateInfo is the document the page renders for the updates card.
type UpdateInfo struct {
	Enabled   bool        `json:"enabled"`
	CheckedAt string      `json:"checked_at,omitempty"`
	Agent     AgentUpdate `json:"agent"`
	App       AppUpdate   `json:"app"`
}

// UpdateChecker looks for newer versions, caching the answer so a page that polls does not turn
// into a stream of requests to Wazuh or the Supervisor.
type UpdateChecker struct {
	Client        *http.Client
	PackagesURL   string
	SupervisorURL string
	Token         string
	Enabled       bool
	Now           func() time.Time

	mu        sync.Mutex
	cached    UpdateInfo
	cachedFor string
	checkedAt time.Time
}

// NewUpdateChecker returns a checker for this machine's architecture.
func NewUpdateChecker(arch, token string, enabled bool) *UpdateChecker {
	return &UpdateChecker{
		Client:        &http.Client{Timeout: 20 * time.Second},
		PackagesURL:   fmt.Sprintf(packagesURLFormat, arch),
		SupervisorURL: supervisorURL,
		Token:         token,
		Enabled:       enabled,
		Now:           time.Now,
	}
}

// Info returns the update information for the installed agent version. A refresh is honoured at
// most once a minute.
func (u *UpdateChecker) Info(ctx context.Context, installed string, refresh bool) UpdateInfo {
	if !u.Enabled {
		return UpdateInfo{Agent: AgentUpdate{Installed: installed}}
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	now := u.Now()
	age := now.Sub(u.checkedAt)
	fresh := !u.checkedAt.IsZero() && u.cachedFor == installed && age < updateTTL
	if fresh && !(refresh && age >= refreshThrottle) {
		return u.cached
	}

	info := UpdateInfo{Enabled: true, CheckedAt: now.UTC().Format(time.RFC3339), Agent: AgentUpdate{Installed: installed}}
	latest, err := u.latestAgent(ctx)
	if err != nil {
		info.Agent.Error = err.Error()
	} else {
		info.Agent.Latest = latest
		info.Agent.Available = newerVersion(latest, installed)
	}
	if u.Token != "" {
		info.App = u.appUpdate(ctx)
	}

	u.cached, u.cachedFor, u.checkedAt = info, installed, now
	return info
}

func (u *UpdateChecker) latestAgent(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.PackagesURL, nil)
	if err != nil {
		return "", fmt.Errorf("could not check Wazuh: %w", err)
	}
	response, err := u.Client.Do(request)
	if err != nil {
		return "", fmt.Errorf("could not reach Wazuh's package repository: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Wazuh's package repository answered %s", response.Status)
	}

	reader, err := gzip.NewReader(io.LimitReader(response.Body, maxIndexBytes))
	if err != nil {
		return "", fmt.Errorf("the package index is not readable: %w", err)
	}
	index, err := io.ReadAll(io.LimitReader(reader, maxIndexBytes))
	if err != nil {
		return "", fmt.Errorf("the package index is not readable: %w", err)
	}
	return NewestAgent(string(index))
}

// NewestAgent finds the highest wazuh-agent version in an apt Packages index.
func NewestAgent(index string) (string, error) {
	best := ""
	for _, stanza := range strings.Split(index, "\n\n") {
		var pkg, version string
		for _, line := range strings.Split(stanza, "\n") {
			switch {
			case strings.HasPrefix(line, "Package: "):
				pkg = strings.TrimPrefix(line, "Package: ")
			case strings.HasPrefix(line, "Version: "):
				version = strings.TrimPrefix(line, "Version: ")
			}
		}
		if pkg != "wazuh-agent" || !versionPattern.MatchString(version) {
			continue
		}
		if best == "" || compareVersions(version, best) > 0 {
			best = version
		}
	}
	if best == "" {
		return "", fmt.Errorf("no wazuh-agent version found in the package index")
	}
	return strings.SplitN(best, "-", 2)[0], nil
}

func (u *UpdateChecker) appUpdate(ctx context.Context) AppUpdate {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.SupervisorURL+"/addons/self/info", nil)
	if err != nil {
		return AppUpdate{Error: err.Error()}
	}
	request.Header.Set("Authorization", "Bearer "+u.Token)
	response, err := u.Client.Do(request)
	if err != nil {
		return AppUpdate{Error: "could not ask the Supervisor: " + err.Error()}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return AppUpdate{Error: "the Supervisor answered " + response.Status}
	}

	var body struct {
		Data struct {
			Version         string `json:"version"`
			VersionLatest   string `json:"version_latest"`
			UpdateAvailable bool   `json:"update_available"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil {
		return AppUpdate{Error: "the Supervisor's answer was not understood"}
	}
	return AppUpdate{Version: body.Data.Version, Latest: body.Data.VersionLatest, Available: body.Data.UpdateAvailable}
}

// compareVersions compares "4.14.9-1" style versions numerically: -1, 0 or 1.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(version string) [4]int {
	var parts [4]int
	match := versionPattern.FindStringSubmatch(version)
	if match == nil {
		// A plain "4.14.9" (no package revision) compares as revision 0.
		match = versionPattern.FindStringSubmatch(version + "-0")
	}
	for i := 0; i < 4 && match != nil; i++ {
		parts[i], _ = strconv.Atoi(match[i+1])
	}
	return parts
}

// newerVersion reports whether latest is a higher version than installed.
func newerVersion(latest, installed string) bool {
	return compareVersions(latest, installed) > 0
}
