package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

type fakeDialer struct {
	fail  map[string]bool
	calls []string
}

func (f *fakeDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	f.calls = append(f.calls, network+" "+address)
	if f.fail[address] {
		return nil, errors.New("connection refused")
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func summaryFor(protocol string, enrollment SummaryEnrollment, addresses ...string) *Summary {
	return &Summary{Manager: SummaryManager{Addresses: addresses, Port: 1514, Protocol: protocol, Enrollment: enrollment}}
}

func TestTargetsFromSummary(t *testing.T) {
	if got := TargetsFromSummary(nil); got != nil {
		t.Errorf("no summary, no targets: %v", got)
	}

	both := TargetsFromSummary(summaryFor("tcp", SummaryEnrollment{Enabled: true, Port: 1515}, "10.0.0.5"))
	want := []Target{{"10.0.0.5", 1514, "events"}, {"10.0.0.5", 1515, "enrollment"}}
	if !reflect.DeepEqual(both, want) {
		t.Errorf("got %v want %v", both, want)
	}

	separate := TargetsFromSummary(summaryFor("tcp", SummaryEnrollment{Enabled: true, Port: 1516, Address: "enroll.lan"}, "10.0.0.5"))
	if separate[1] != (Target{"enroll.lan", 1516, "enrollment"}) {
		t.Errorf("a separate enrollment server must be used: %v", separate)
	}

	off := TargetsFromSummary(summaryFor("tcp", SummaryEnrollment{}, "10.0.0.5"))
	if len(off) != 1 {
		t.Errorf("with enrollment off only the event port matters: %v", off)
	}

	twice := TargetsFromSummary(summaryFor("tcp", SummaryEnrollment{Enabled: true, Port: 1515}, "10.0.0.5", "10.0.0.5"))
	if len(twice) != 2 {
		t.Errorf("the same target must not be tried twice: %v", twice)
	}
}

func TestCheckConnections(t *testing.T) {
	dialer := &fakeDialer{fail: map[string]bool{"10.0.0.5:1515": true}}
	targets := []Target{{"10.0.0.5", 1514, "events"}, {"10.0.0.5", 1515, "enrollment"}}
	results := CheckConnections(context.Background(), dialer, targets, "tcp", time.Second)

	if len(results) != 2 || !results[0].Tested || !results[0].Reachable {
		t.Fatalf("events should be reachable: %+v", results)
	}
	if !results[1].Tested || results[1].Reachable || results[1].Note != "connection refused" {
		t.Errorf("enrollment should fail with the reason: %+v", results[1])
	}
	if !reflect.DeepEqual(dialer.calls, []string{"tcp 10.0.0.5:1514", "tcp 10.0.0.5:1515"}) {
		t.Errorf("calls: %v", dialer.calls)
	}
}

func TestCheckConnectionsDoesNotPretendToTestUDP(t *testing.T) {
	dialer := &fakeDialer{}
	targets := []Target{{"10.0.0.5", 1514, "events"}, {"10.0.0.5", 1515, "enrollment"}}
	results := CheckConnections(context.Background(), dialer, targets, "udp", time.Second)
	if results[0].Tested || results[0].Note == "" {
		t.Errorf("UDP events cannot be tested: %+v", results[0])
	}
	if !results[1].Tested || len(dialer.calls) != 1 {
		t.Errorf("enrollment is always TCP and must still be tested: %+v calls=%v", results[1], dialer.calls)
	}
}

func TestCheckConnectionsWithNoTargets(t *testing.T) {
	if got := CheckConnections(context.Background(), &fakeDialer{}, nil, "tcp", time.Second); got == nil || len(got) != 0 {
		t.Errorf("want an empty, non-nil list (it becomes [] in JSON), got %#v", got)
	}
}
