package main

import (
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"path"
	"time"
)

const connectionTimeout = 3 * time.Second

// Server answers the page's requests. It is read-only: every route is a GET.
type Server struct {
	Config  Config
	Public  fs.FS
	Static  fs.FS
	Updates *UpdateChecker
	Dialer  Dialer
	Now     func() time.Time
}

// Handler returns the whole HTTP handler: the allow list in front of the API and the page.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/updates", s.updates)
	mux.HandleFunc("GET /api/logs", s.logs)
	mux.HandleFunc("GET /api/connection-test", s.connectionTest)
	mux.Handle("GET /", http.FileServerFS(noListing{s.Static}))
	return s.secure(mux)
}

// secure refuses everyone except the allowed networks and puts the security headers on every
// response. Inside Home Assistant the only legitimate client is the Supervisor's ingress gateway,
// and X-Forwarded-For is deliberately not consulted: it can be set by whoever sends the request.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		header := w.Header()
		header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowed(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range s.Config.Allow {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, BuildStatus(s.Public, s.now()))
}

func (s *Server) updates(w http.ResponseWriter, r *http.Request) {
	installed := ""
	if summary := readSummary(s.Public); summary != nil {
		installed = summary.Agent.Version
	}
	writeJSON(w, s.Updates.Info(r.Context(), installed, r.URL.Query().Get("refresh") == "1"))
}

func (s *Server) logs(w http.ResponseWriter, _ *http.Request) {
	data, _ := fs.ReadFile(s.Public, fileLog)
	writeJSON(w, map[string][]string{"lines": ParseLogTail(string(data))})
}

func (s *Server) connectionTest(w http.ResponseWriter, r *http.Request) {
	summary := readSummary(s.Public)
	protocol := ""
	if summary != nil {
		protocol = summary.Manager.Protocol
	}
	results := CheckConnections(r.Context(), s.Dialer, TargetsFromSummary(summary), protocol, connectionTimeout)
	writeJSON(w, map[string]any{"results": results})
}

// noListing serves files, and a directory only through its index.html: never a listing.
type noListing struct{ fs fs.FS }

func (n noListing) Open(name string) (fs.File, error) {
	file, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		index, err := n.fs.Open(path.Join(name, "index.html"))
		if err != nil {
			_ = file.Close()
			return nil, fs.ErrNotExist
		}
		_ = index.Close()
	}
	return file, nil
}
