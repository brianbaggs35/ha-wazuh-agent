package main

import (
	"context"
	"net"
	"strconv"
	"time"
)

// Dialer is the part of net.Dialer the connection test needs.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Target is one address and port the agent needs to reach.
type Target struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Purpose string `json:"purpose"`
}

// ConnectionResult is the outcome of trying one target.
type ConnectionResult struct {
	Target
	Tested    bool   `json:"tested"`
	Reachable bool   `json:"reachable"`
	Millis    int64  `json:"millis,omitempty"`
	Note      string `json:"note,omitempty"`
}

// TargetsFromSummary lists what the agent must reach: the manager's event port and, when
// automatic enrollment is on, the enrollment port.
func TargetsFromSummary(summary *Summary) []Target {
	if summary == nil {
		return nil
	}
	var targets []Target
	for _, host := range summary.Manager.Addresses {
		targets = append(targets, Target{Host: host, Port: summary.Manager.Port, Purpose: "events"})
		if summary.Manager.Enrollment.Enabled {
			enrollHost := host
			if summary.Manager.Enrollment.Address != "" {
				enrollHost = summary.Manager.Enrollment.Address
			}
			targets = append(targets, Target{Host: enrollHost, Port: summary.Manager.Enrollment.Port, Purpose: "enrollment"})
		}
	}
	return dedupe(targets)
}

func dedupe(targets []Target) []Target {
	seen := map[Target]bool{}
	unique := targets[:0:0]
	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			unique = append(unique, target)
		}
	}
	return unique
}

// CheckConnections tries a TCP connection to each target. UDP event traffic cannot be tested
// this way, so the event port is reported as not tested when the agent uses UDP.
func CheckConnections(ctx context.Context, dialer Dialer, targets []Target, protocol string, timeout time.Duration) []ConnectionResult {
	results := make([]ConnectionResult, 0, len(targets))
	for _, target := range targets {
		result := ConnectionResult{Target: target}
		if protocol == "udp" && target.Purpose == "events" {
			result.Note = "The agent sends events over UDP, which cannot be tested here."
			results = append(results, result)
			continue
		}

		attempt, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		conn, err := dialer.DialContext(attempt, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
		cancel()

		result.Tested = true
		result.Millis = time.Since(started).Milliseconds()
		if err != nil {
			result.Note = err.Error()
		} else {
			result.Reachable = true
			_ = conn.Close()
		}
		results = append(results, result)
	}
	return results
}
