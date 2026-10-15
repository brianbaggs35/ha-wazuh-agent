package main

import (
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8099" || cfg.PublicDir != "/run/wazuh-ha/public" || cfg.StaticDir != "/usr/share/wazuh-ha-ui" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if !cfg.UpdateCheck {
		t.Error("update check should default to on")
	}
	if len(cfg.Allow) != 1 || cfg.Allow[0].String() != "172.30.32.2/32" {
		t.Errorf("the default allow list must be the Supervisor's ingress gateway, got %v", cfg.Allow)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	cfg, err := LoadConfig(env(map[string]string{
		"WAZUH_UI_LISTEN":       " 127.0.0.1:9000 ",
		"WAZUH_UI_ALLOW":        "10.0.0.0/8, ::1",
		"WAZUH_UI_PUBLIC_DIR":   "/tmp/public",
		"WAZUH_UI_STATIC_DIR":   "/tmp/static",
		"WAZUH_UI_UPDATE_CHECK": "false",
		"SUPERVISOR_TOKEN":      "token",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9000" || cfg.PublicDir != "/tmp/public" || cfg.StaticDir != "/tmp/static" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.UpdateCheck || cfg.SupervisorToken != "token" || len(cfg.Allow) != 2 {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadConfigRejectsABadAllowList(t *testing.T) {
	_, err := LoadConfig(env(map[string]string{"WAZUH_UI_ALLOW": "not-an-address"}))
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseAllowList(t *testing.T) {
	cases := []struct {
		name    string
		list    string
		want    []string
		wantErr string
	}{
		{"a single address is one host", "172.30.32.2", []string{"172.30.32.2/32"}, ""},
		{"an IPv6 address is one host", "::1", []string{"::1/128"}, ""},
		{"a network", "10.0.0.0/8", []string{"10.0.0.0/8"}, ""},
		{"spaces and empty items are ignored", " 10.0.0.1 , ,192.168.0.0/16 ", []string{"10.0.0.1/32", "192.168.0.0/16"}, ""},
		{"a bad address", "10.0.0", nil, "not an IP address"},
		{"a bad network", "10.0.0.0/99", nil, "not an IP address"},
		{"nothing at all", " , ", nil, "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			networks, err := ParseAllowList(c.list)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want an error containing %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, network := range networks {
				got = append(got, network.String())
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
