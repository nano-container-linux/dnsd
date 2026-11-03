package dnsd

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func reserveHealthTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve health tcp port: %v", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("failed to resolve health tcp addr")
	}
	return uint16(addr.Port)
}

func TestResolveHealthListenNilConfig(t *testing.T) {
	_, _, _, _, err := resolveHealthListen(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestResolveHealthListenDefaults(t *testing.T) {
	cfg := &HealthConfig{Addr: "127.0.0.1", Port: 8081, Allow: []string{"127.0.0.1"}, Deny: []string{}}
	addr, network, readinessPath, livenessPath, err := resolveHealthListen(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "127.0.0.1:8081" {
		t.Fatalf("unexpected addr: %s", addr)
	}
	if network != "tcp" {
		t.Fatalf("unexpected network: %s", network)
	}
	if readinessPath != "/readyz" {
		t.Fatalf("unexpected readiness path: %s", readinessPath)
	}
	if livenessPath != "/healthz" {
		t.Fatalf("unexpected liveness path: %s", livenessPath)
	}
}

func TestHealthEndpoints(t *testing.T) {
	runtime := &RuntimeConfig{UpstreamHealth: map[string]*upstreamHealth{}}
	port := reserveHealthTCPPort(t)
	errCh := make(chan error, 1)
	cfg := &HealthConfig{
		Addr:          "127.0.0.1",
		Port:          port,
		Net:           "tcp",
		ReadinessPath: "/readyz",
		LivenessPath:  "/healthz",
		Allow:         []string{"127.0.0.1", "::1"},
		Deny:          []string{},
	}
	if err := startHealthServer(runtime, cfg, errCh); err != nil {
		t.Fatalf("startHealthServer returned error: %v", err)
	}

	check := func(path string) int {
		url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
		deadline := time.Now().Add(5 * time.Second)
		for {
			select {
			case err := <-errCh:
				t.Fatalf("health server exited unexpectedly: %v", err)
			default:
			}
			resp, err := http.Get(url)
			if err == nil {
				_ = resp.Body.Close()
				return resp.StatusCode
			}
			if time.Now().After(deadline) {
				t.Fatalf("health endpoint did not come up: %s", url)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	if status := check("/readyz"); status != http.StatusOK {
		t.Fatalf("unexpected readiness status: %d", status)
	}
	if status := check("/healthz"); status != http.StatusOK {
		t.Fatalf("unexpected liveness status: %d", status)
	}
}

func TestHealthReadinessUnhealthyUpstream(t *testing.T) {
	runtime := &RuntimeConfig{UpstreamHealth: map[string]*upstreamHealth{
		"8.8.8.8:53": {down: true, downUntil: time.Now().Add(5 * time.Minute)},
	}}
	h := newHealthHTTPHandler(runtime, "/readyz", "/healthz", bindACLRuntime{allow: mustPrefixes(t, "127.0.0.1")})
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: h}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	url := fmt.Sprintf("http://%s/readyz", ln.Addr().String())
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}
