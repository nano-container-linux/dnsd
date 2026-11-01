package dnsd

import "testing"

func TestResolveMetricsListenDefaults(t *testing.T) {
	addr, network, path, err := resolveMetricsListen(&MetricsConfig{
		Addr: "127.0.0.1",
		Port: 9090,
	})
	if err != nil {
		t.Fatalf("resolveMetricsListen() error = %v", err)
	}
	if addr != "127.0.0.1:9090" {
		t.Fatalf("unexpected addr: %s", addr)
	}
	if network != "tcp" {
		t.Fatalf("expected default network tcp, got %s", network)
	}
	if path != "/metrics" {
		t.Fatalf("expected default path /metrics, got %s", path)
	}
}

func TestResolveMetricsListenInvalidNet(t *testing.T) {
	_, _, _, err := resolveMetricsListen(&MetricsConfig{
		Addr: "127.0.0.1",
		Port: 9090,
		Net:  "udp",
	})
	if err == nil {
		t.Fatal("expected resolveMetricsListen to fail for non-tcp net")
	}
}
