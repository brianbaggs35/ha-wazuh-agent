package main

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

var epoch = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const daemonsRunning = `wazuh-modulesd is running...
wazuh-logcollector is running...
wazuh-syscheckd is running...
wazuh-agentd is running...
wazuh-execd is running...
`

const stateConnected = `# State file for wazuh-agentd
last_keepalive='2026-10-15 11:59:50'
last_ack='2026-10-15 11:59:51'
msg_count='34'
msg_sent='36'
msg_buffer='0'
status='connected'
`

const expectedAll = "wazuh-agentd\nwazuh-execd\nwazuh-logcollector\nwazuh-modulesd\nwazuh-syscheckd\n"

const summaryJSON = `{"agent":{"name":"homeassistant","groups":["default"],"config_profile":"homeassistant","version":"4.14.9"},
 "manager":{"addresses":["10.0.0.5"],"port":1514,"protocol":"tcp","enrollment":{"enabled":true,"address":"","port":1515,"password_set":false,"verified":false}},
 "modules":{"fim":true},"host":{"hostname":"homeassistant"},"app":{"version":"1.0.0"}}`

func files(fresh bool, extra map[string]string) fstest.MapFS {
	modTime := epoch.Add(-5 * time.Second)
	if !fresh {
		modTime = epoch.Add(-10 * time.Minute)
	}
	fsys := fstest.MapFS{
		"daemons.txt":   {Data: []byte(daemonsRunning), ModTime: modTime},
		"expected.txt":  {Data: []byte(expectedAll)},
		"agentd.state":  {Data: []byte(stateConnected)},
		"identity.json": {Data: []byte(`{"id":"001","name":"homeassistant"}`)},
		"summary.json":  {Data: []byte(summaryJSON)},
	}
	for name, data := range extra {
		fsys[name] = &fstest.MapFile{Data: []byte(data), ModTime: modTime}
	}
	return fsys
}

func TestParseDaemons(t *testing.T) {
	got := ParseDaemons("wazuh-agentd is running...\nwazuh-syscheckd not running...\nnoise line\nwazuh-x\n\n")
	want := map[string]bool{"wazuh-agentd": true, "wazuh-syscheckd": false}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParseExpected(t *testing.T) {
	got := ParseExpected(" wazuh-agentd \n\nwazuh-execd\n")
	if !got["wazuh-agentd"] || !got["wazuh-execd"] || len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

func inZone(t *testing.T, name string, offsetSeconds int) {
	t.Helper()
	restore := time.Local
	time.Local = time.FixedZone(name, offsetSeconds)
	t.Cleanup(func() { time.Local = restore })
}

func TestParseAgentState(t *testing.T) {
	inZone(t, "UTC", 0)
	got := ParseAgentState(stateConnected)
	want := Connection{Status: "connected", LastKeepalive: "2026-10-15T11:59:50Z", LastAck: "2026-10-15T11:59:51Z", MessagesSent: "36", Buffered: "0"}
	if got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
	if empty := ParseAgentState("garbage\n# comment=ignored\n"); empty != (Connection{}) {
		t.Errorf("unexpected values from garbage: %+v", empty)
	}
}

func TestAgentTimesCarryTheContainersTimeZone(t *testing.T) {
	inZone(t, "CET", 2*3600)
	if got := localTimeToRFC3339("2026-10-15 11:59:50"); got != "2026-10-15T11:59:50+02:00" {
		t.Errorf("got %q", got)
	}
	for _, unparsable := range []string{"", "yesterday", "2026-10-15"} {
		if got := localTimeToRFC3339(unparsable); got != unparsable {
			t.Errorf("%q must pass through unchanged, got %q", unparsable, got)
		}
	}
}

func TestParseIdentity(t *testing.T) {
	if got := ParseIdentity([]byte(`{"id":"007","name":"bond"}`)); !got.Registered || got.ID != "007" || got.Name != "bond" {
		t.Errorf("got %+v", got)
	}
	for _, bad := range []string{"", "not json", `{"id":""}`, `{}`} {
		if got := ParseIdentity([]byte(bad)); got.Registered {
			t.Errorf("%q should not be registered: %+v", bad, got)
		}
	}
}

func TestBuildStatusStartingWhenNothingIsPublished(t *testing.T) {
	status := BuildStatus(fstest.MapFS{}, epoch)
	if status.State != "starting" || len(status.Daemons) != 0 {
		t.Errorf("got %+v", status)
	}
}

func TestBuildStatusRunning(t *testing.T) {
	status := BuildStatus(files(true, nil), epoch)
	if status.State != "running" || status.Headline != "Running and connected" {
		t.Fatalf("got %s / %s", status.State, status.Headline)
	}
	if len(status.Daemons) != 5 || status.Daemons[0].Name != "wazuh-agentd" || !status.Daemons[0].Expected {
		t.Errorf("daemons not sorted or not marked expected: %+v", status.Daemons)
	}
	if !status.Registration.Registered || status.Registration.ID != "001" {
		t.Errorf("registration: %+v", status.Registration)
	}
	if status.Connection.Status != "connected" || status.Summary == nil || status.Summary.Agent.Version != "4.14.9" {
		t.Errorf("connection/summary: %+v %+v", status.Connection, status.Summary)
	}
	if status.UpdatedAt != "2026-10-15T11:59:55Z" {
		t.Errorf("updated_at: %q", status.UpdatedAt)
	}
}

func TestBuildStatusStates(t *testing.T) {
	cases := []struct {
		name   string
		daemon string
		state  string
		want   string
	}{
		{"agent stopped", strings.Replace(daemonsRunning, "wazuh-agentd is running", "wazuh-agentd not running", 1), "status='connected'", "stopped"},
		{"another daemon missing", strings.Replace(daemonsRunning, "wazuh-syscheckd is running", "wazuh-syscheckd not running", 1), "status='connected'", "degraded"},
		{"manager unreachable", daemonsRunning, "status='disconnected'", "disconnected"},
		{"still connecting", daemonsRunning, "status='pending'", "connecting"},
		{"no state yet", daemonsRunning, "", "connecting"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status := BuildStatus(files(true, map[string]string{"daemons.txt": c.daemon, "agentd.state": c.state}), epoch)
			if status.State != c.want {
				t.Errorf("got %q (%s), want %q", status.State, status.Detail, c.want)
			}
			if status.Headline == "" || status.Detail == "" {
				t.Error("a state needs a headline and a sentence for the user")
			}
		})
	}
}

func TestBuildStatusIgnoresDaemonsThatWereNeverExpected(t *testing.T) {
	status := BuildStatus(files(true, map[string]string{
		"daemons.txt":  strings.Replace(daemonsRunning, "wazuh-syscheckd is running", "wazuh-syscheckd not running", 1),
		"expected.txt": "wazuh-agentd\nwazuh-execd\n",
	}), epoch)
	if status.State != "running" {
		t.Errorf("a daemon switched off by configuration must not degrade the state: %s", status.State)
	}
}

func TestBuildStatusStale(t *testing.T) {
	status := BuildStatus(files(false, nil), epoch)
	if status.State != "stale" {
		t.Errorf("got %q", status.State)
	}
}

func TestBuildStatusWithoutOptionalFiles(t *testing.T) {
	fsys := fstest.MapFS{"daemons.txt": {Data: []byte(daemonsRunning), ModTime: epoch}}
	status := BuildStatus(fsys, epoch)
	if status.Summary != nil || status.Registration.Registered || status.State != "connecting" {
		t.Errorf("got %+v", status)
	}
}

func TestBuildStatusWithAnUnreadableSummary(t *testing.T) {
	status := BuildStatus(files(true, map[string]string{"summary.json": "{broken"}), epoch)
	if status.Summary != nil {
		t.Error("a broken summary must be ignored")
	}
}

// statFails reads fine but cannot be stat'ed, as a file on a failing disk might.
type statFails struct{ fstest.MapFS }

func (statFails) Stat(string) (fs.FileInfo, error) { return nil, errors.New("stat failed") }

func TestBuildStatusWhenTheFileCannotBeStatted(t *testing.T) {
	status := BuildStatus(statFails{files(true, nil)}, epoch)
	if status.UpdatedAt != "" || status.State == "stale" {
		t.Errorf("without a time the status cannot be called stale: %+v", status)
	}
}

func TestParseLogTail(t *testing.T) {
	if got := ParseLogTail(""); len(got) != 0 {
		t.Errorf("empty log: %v", got)
	}
	if got := ParseLogTail("a\nb\n"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("got %v", got)
	}
	var many []string
	for i := 0; i < maxLogLines+20; i++ {
		many = append(many, "line")
	}
	if got := ParseLogTail(strings.Join(many, "\n")); len(got) != maxLogLines {
		t.Errorf("tail not limited: %d", len(got))
	}
	long := strings.Repeat("x", maxLogLine+50)
	if got := ParseLogTail(long); len(got[0]) <= maxLogLine || !strings.HasSuffix(got[0], "…") || len(got[0]) > maxLogLine+4 {
		t.Errorf("long line not shortened: %d", len(got[0]))
	}
}
