package dnsd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func reserveMetricsTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve tcp port: %v", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("failed to resolve tcp addr")
	}
	return uint16(addr.Port)
}

func TestMetricsEndpoint_ExposesPrometheus(t *testing.T) {
	metricsPort := reserveMetricsTCPPort(t)
	errCh := make(chan error, 1)
	cfg := &MetricsConfig{
		Addr:  "127.0.0.1",
		Port:  metricsPort,
		Net:   "tcp",
		Path:  "/metrics",
		Allow: []string{"127.0.0.1", "::1"},
		Deny:  []string{},
	}

	if err := startMetricsServer(cfg, errCh); err != nil {
		t.Fatalf("startMetricsServer returned error: %v", err)
	}

	observeDNSQuestion(dns.TypeA)
	observeDNSResponse(dns.RcodeSuccess)
	observeDynamicSubmission("accepted")

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("metrics server exited unexpectedly: %v", err)
		default:
		}

		resp, err := http.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				text := string(body)
				if strings.Contains(text, "dnsd_dns_questions_total") &&
					strings.Contains(text, "dnsd_dns_responses_total") &&
					strings.Contains(text, "dnsd_dynamic_submissions_total") {
					return
				}
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("metrics endpoint not ready or missing expected metrics: %s", url)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMetricsEndpoint_CustomPath(t *testing.T) {
	metricsPort := reserveMetricsTCPPort(t)
	errCh := make(chan error, 1)
	cfg := &MetricsConfig{
		Addr:  "127.0.0.1",
		Port:  metricsPort,
		Net:   "tcp",
		Path:  "/prom",
		Allow: []string{"127.0.0.1", "::1"},
		Deny:  []string{},
	}

	if err := startMetricsServer(cfg, errCh); err != nil {
		t.Fatalf("startMetricsServer returned error: %v", err)
	}

	observeDNSQuestion(dns.TypeAAAA)
	observeDNSResponse(dns.RcodeSuccess)
	observeDynamicSubmission("accepted")

	url := fmt.Sprintf("http://127.0.0.1:%d/prom", metricsPort)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("metrics server exited unexpectedly: %v", err)
		default:
		}

		resp, err := http.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				text := string(body)
				if strings.Contains(text, "dnsd_dns_questions_total") {
					break
				}
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("custom metrics endpoint not ready or missing expected metrics: %s", url)
		}
		time.Sleep(100 * time.Millisecond)
	}

	defaultResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	if err == nil {
		_ = defaultResp.Body.Close()
		if defaultResp.StatusCode == http.StatusOK {
			t.Fatal("expected /metrics not to be exposed when custom path is /prom")
		}
	}
}

func TestMetricsEndpointACL_DenyLocalhost(t *testing.T) {
	metricsPort := reserveMetricsTCPPort(t)
	errCh := make(chan error, 1)
	cfg := &MetricsConfig{
		Addr:  "127.0.0.1",
		Port:  metricsPort,
		Net:   "tcp",
		Path:  "/metrics",
		Deny:  []string{"127.0.0.1", "::1"},
		Allow: []string{},
	}

	if err := startMetricsServer(cfg, errCh); err != nil {
		t.Fatalf("startMetricsServer returned error: %v", err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("metrics server exited unexpectedly: %v", err)
		default:
		}

		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("metrics endpoint should be forbidden by ACL: %s", url)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
