package main

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"strings"
	"time"
)

// The root-owned supervisor service in the app publishes these files every few seconds. They hold
// no secrets: daemon states, the agent's connection state, the registration identity (never the
// key), a summary of the configuration and a tail of the agent log.
const (
	fileDaemons  = "daemons.txt"
	fileExpected = "expected.txt"
	fileState    = "agentd.state"
	fileIdentity = "identity.json"
	fileSummary  = "summary.json"
	fileAccess   = "access.json"
	fileLog      = "log.txt"

	// How old the published files may be before the status is reported as stale.
	staleAfter = 45 * time.Second

	maxLogLines = 300
	maxLogLine  = 1000
)

// Daemon is one Wazuh agent daemon and whether it is running.
type Daemon struct {
	Name     string `json:"name"`
	Running  bool   `json:"running"`
	Expected bool   `json:"expected"`
}

// Connection is what wazuh-agentd reports about its link to the manager.
type Connection struct {
	Status        string `json:"status"`
	LastKeepalive string `json:"last_keepalive,omitempty"`
	LastAck       string `json:"last_ack,omitempty"`
	MessagesSent  string `json:"messages_sent,omitempty"`
	Buffered      string `json:"buffered,omitempty"`
}

// Registration says whether the agent has a key from the manager.
type Registration struct {
	Registered bool   `json:"registered"`
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
}

// Summary is the configuration summary written by the init step.
type Summary struct {
	Agent   SummaryAgent    `json:"agent"`
	Manager SummaryManager  `json:"manager"`
	Modules map[string]bool `json:"modules"`
	Host    map[string]any  `json:"host"`
	App     SummaryApp      `json:"app"`
}

type SummaryAgent struct {
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	ConfigProfile string   `json:"config_profile"`
	Version       string   `json:"version"`
}

type SummaryManager struct {
	Addresses  []string          `json:"addresses"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Enrollment SummaryEnrollment `json:"enrollment"`
}

type SummaryEnrollment struct {
	Enabled     bool   `json:"enabled"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	PasswordSet bool   `json:"password_set"`
	Verified    bool   `json:"verified"`
}

type SummaryApp struct {
	Version string `json:"version"`
}

// Access says where the agent was asked to run and whether it can. Scope is "host" (the Home
// Assistant OS device itself) or "container" (only this app's own). Available is false when the agent
// was not started because the host cannot be reached (Protection mode is on, ...): Reason is a short
// code and Message a sentence the user can act on.
type Access struct {
	Scope     string `json:"scope"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Status is the one document the page renders.
type Status struct {
	State        string       `json:"state"`
	Headline     string       `json:"headline"`
	Detail       string       `json:"detail"`
	UpdatedAt    string       `json:"updated_at,omitempty"`
	Daemons      []Daemon     `json:"daemons"`
	Connection   Connection   `json:"connection"`
	Registration Registration `json:"registration"`
	Summary      *Summary     `json:"summary,omitempty"`
	Access       *Access      `json:"access,omitempty"`
}

// ParseDaemons reads `wazuh-control status` output: "<daemon> is running..." / "<daemon> not running...".
func ParseDaemons(text string) map[string]bool {
	daemons := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "wazuh-") {
			continue
		}
		daemons[fields[0]] = fields[1] == "is"
	}
	return daemons
}

// ParseExpected reads the list of daemons that were running after start-up, one per line.
func ParseExpected(text string) map[string]bool {
	expected := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			expected[name] = true
		}
	}
	return expected
}

// ParseAgentState reads wazuh-agentd.state: lines of key='value'.
func ParseAgentState(text string) Connection {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, found := strings.Cut(line, "=")
		if !found || strings.HasPrefix(line, "#") {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), "'")
	}
	return Connection{
		Status:        values["status"],
		LastKeepalive: localTimeToRFC3339(values["last_keepalive"]),
		LastAck:       localTimeToRFC3339(values["last_ack"]),
		MessagesSent:  values["msg_sent"],
		Buffered:      values["msg_buffer"],
	}
}

// localTimeToRFC3339 gives the agent's "2006-01-02 15:04:05" timestamps (written in the container's
// time zone, which Home Assistant sets) an explicit offset, so a browser in another time zone reads
// them correctly. Anything that does not parse is passed through unchanged.
func localTimeToRFC3339(value string) string {
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", value, time.Local)
	if err != nil {
		return value
	}
	return parsed.Format(time.RFC3339)
}

// ParseIdentity reads identity.json. A missing or unreadable file means "not registered".
func ParseIdentity(data []byte) Registration {
	var identity Registration
	if err := json.Unmarshal(data, &identity); err != nil {
		return Registration{}
	}
	if identity.ID == "" {
		return Registration{}
	}
	identity.Registered = true
	return identity
}

// BuildStatus assembles the status from the published files.
func BuildStatus(fsys fs.FS, now time.Time) Status {
	status := Status{Daemons: []Daemon{}, Access: readAccess(fsys)}

	// An agent that was never started, because the host it was asked to monitor cannot be reached, has
	// nothing else to show: say what is needed, ahead of everything that is only a symptom of it.
	if status.Access != nil && !status.Access.Available {
		status.State, status.Headline = "needs_host_access", "Host access is needed"
		status.Detail = valueOr(status.Access.Message, "The agent could not be started on the Home Assistant OS host. Check the app log.")
		status.Summary = readSummary(fsys)
		return status
	}

	daemonsText, err := fs.ReadFile(fsys, fileDaemons)
	if err != nil {
		status.State, status.Headline = "starting", "Starting"
		status.Detail = "The agent is starting up. This page fills in once the first status has been written."
		return status
	}
	if info, statErr := fs.Stat(fsys, fileDaemons); statErr == nil {
		status.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
		if now.Sub(info.ModTime()) > staleAfter {
			status.State, status.Headline = "stale", "Status is not updating"
			status.Detail = "The service that publishes the agent's status has stopped. Restart the app."
		}
	}

	expectedText, _ := fs.ReadFile(fsys, fileExpected)
	expected := ParseExpected(string(expectedText))
	for name, running := range ParseDaemons(string(daemonsText)) {
		status.Daemons = append(status.Daemons, Daemon{Name: name, Running: running, Expected: expected[name]})
	}
	sortDaemons(status.Daemons)

	stateText, _ := fs.ReadFile(fsys, fileState)
	status.Connection = ParseAgentState(string(stateText))
	identityData, _ := fs.ReadFile(fsys, fileIdentity)
	status.Registration = ParseIdentity(identityData)
	status.Summary = readSummary(fsys)

	if status.State == "" {
		status.State, status.Headline, status.Detail = deriveState(status.Daemons, status.Connection.Status)
	}
	return status
}

func sortDaemons(daemons []Daemon) {
	for i := 1; i < len(daemons); i++ {
		for j := i; j > 0 && daemons[j].Name < daemons[j-1].Name; j-- {
			daemons[j], daemons[j-1] = daemons[j-1], daemons[j]
		}
	}
}

func readAccess(fsys fs.FS) *Access {
	data, err := fs.ReadFile(fsys, fileAccess)
	if err != nil {
		return nil
	}
	var access Access
	if err := json.Unmarshal(data, &access); err != nil {
		return nil
	}
	return &access
}

func readSummary(fsys fs.FS) *Summary {
	data, err := fs.ReadFile(fsys, fileSummary)
	if err != nil {
		return nil
	}
	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil
	}
	return &summary
}

// deriveState turns daemon and connection facts into one state and a sentence a person can act on.
func deriveState(daemons []Daemon, connection string) (state, headline, detail string) {
	agentRunning, missing := false, ""
	for _, daemon := range daemons {
		if daemon.Name == "wazuh-agentd" {
			agentRunning = daemon.Running
		}
		if daemon.Expected && !daemon.Running && missing == "" {
			missing = daemon.Name
		}
	}

	switch {
	case !agentRunning:
		return "stopped", "Agent stopped", "The Wazuh agent is not running. The app restarts it automatically; if this stays, check the app log."
	case connection == "connected" && missing == "":
		return "running", "Running and connected", "The agent is connected to the Wazuh manager and sending events."
	case connection == "connected":
		return "degraded", "Running with a problem", missing + " is not running. The app will restart the agent if it does not come back."
	case connection == "disconnected":
		return "disconnected", "Cannot reach the manager", "The agent is running but is not connected. Check the manager address, ports 1514 and 1515, and the manager's log."
	default:
		return "connecting", "Connecting", "The agent is starting its connection to the manager."
	}
}

// ParseLogTail returns the last lines of the agent log, each capped in length.
func ParseLogTail(text string) []string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []string{}
	}
	if len(lines) > maxLogLines {
		lines = lines[len(lines)-maxLogLines:]
	}
	for i, line := range lines {
		if len(line) > maxLogLine {
			lines[i] = line[:maxLogLine] + "…"
		}
	}
	return lines
}
