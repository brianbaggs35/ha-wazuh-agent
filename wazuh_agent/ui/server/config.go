package main

import (
	"fmt"
	"net"
	"strings"
)

// Defaults match the paths the app's init step and service use inside the container.
const (
	defaultListen    = ":8099"
	defaultAllow     = "172.30.32.2"
	defaultPublicDir = "/run/wazuh-ha/public"
	defaultStaticDir = "/usr/share/wazuh-ha-ui"
)

// Config is everything the server needs from its environment.
type Config struct {
	Listen          string
	Allow           []*net.IPNet
	PublicDir       string
	StaticDir       string
	SupervisorToken string
	UpdateCheck     bool
}

// LoadConfig reads the configuration from environment variables through getenv.
//
// Nothing here can point the server at a different update source or Supervisor: the URLs are
// fixed in code, so no setting can turn the update check into a request to an address of
// someone's choosing.
func LoadConfig(getenv func(string) string) (Config, error) {
	cfg := Config{
		Listen:          valueOr(getenv("WAZUH_UI_LISTEN"), defaultListen),
		PublicDir:       valueOr(getenv("WAZUH_UI_PUBLIC_DIR"), defaultPublicDir),
		StaticDir:       valueOr(getenv("WAZUH_UI_STATIC_DIR"), defaultStaticDir),
		SupervisorToken: getenv("SUPERVISOR_TOKEN"),
		UpdateCheck:     getenv("WAZUH_UI_UPDATE_CHECK") != "false",
	}

	allow, err := ParseAllowList(valueOr(getenv("WAZUH_UI_ALLOW"), defaultAllow))
	if err != nil {
		return Config{}, err
	}
	cfg.Allow = allow
	return cfg, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// ParseAllowList turns "172.30.32.2, 10.0.0.0/8" into networks. A bare address is a single host.
func ParseAllowList(list string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("allow list: %q is not an IP address or CIDR", item)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("allow list: %q is not an IP address or CIDR", item)
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, fmt.Errorf("allow list is empty: refusing to serve anyone")
	}
	return networks, nil
}
