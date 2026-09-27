package dnsd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestLoadConfigFromTestdataAllRecordTypes(t *testing.T) {
	cfg, err := loadConfig("testdata/config_full")
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if len(cfg.Zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(cfg.Zones))
	}

	aOwner := "registry.example.com."
	aaaaOwner := "v6.example.com."
	srvOwner := "_oci._tcp.example.com."
	cnameOwner := "www.example.com."
	txtOwner := "txt.example.com."
	ptrOwner := "2.0.168.192.in-addr.arpa."
	mxOwner := "mail.example.com."
	nsOwner := "ns-rec.example.com."
	soaOwner := "soa-rec.example.com."
	certOwner := "cert-rec.example.com."
	rpOwner := "rp-rec.example.com."
	sshfpOwner := "ssh-rec.example.com."

	a := requireSingleRR[*dns.A](t, cfg, dns.TypeA, aOwner)
	if a.Hdr.Ttl != 1234 {
		t.Fatalf("expected A TTL overridden to 1234, got %d", a.Hdr.Ttl)
	}

	aaaa := requireSingleRR[*dns.AAAA](t, cfg, dns.TypeAAAA, aaaaOwner)
	if aaaa.Hdr.Name != aaaaOwner {
		t.Fatalf("unexpected AAAA owner: %s", aaaa.Hdr.Name)
	}

	srv := requireSingleRR[*dns.SRV](t, cfg, dns.TypeSRV, srvOwner)
	if srv.Target != "registry.example.com." || srv.Port != 5000 {
		t.Fatalf("unexpected SRV record: %+v", srv)
	}

	cname := requireSingleRR[*dns.CNAME](t, cfg, dns.TypeCNAME, cnameOwner)
	if cname.Target != "registry.example.com." {
		t.Fatalf("unexpected CNAME record: %+v", cname)
	}

	txt := requireSingleRR[*dns.TXT](t, cfg, dns.TypeTXT, txtOwner)
	if len(txt.Txt) != 3 {
		t.Fatalf("unexpected TXT record: %+v", txt)
	}

	ptr := requireSingleRR[*dns.PTR](t, cfg, dns.TypePTR, ptrOwner)
	if ptr.Ptr != "registry.example.com." {
		t.Fatalf("unexpected PTR record: %+v", ptr)
	}

	mx := requireSingleRR[*dns.MX](t, cfg, dns.TypeMX, mxOwner)
	if mx.Preference != 20 || mx.Mx != "mxhost.example.com." {
		t.Fatalf("unexpected MX record: %+v", mx)
	}

	ns := requireSingleRR[*dns.NS](t, cfg, dns.TypeNS, nsOwner)
	if ns.Ns != "ns1.example.com." {
		t.Fatalf("unexpected NS record: %+v", ns)
	}

	soa := requireSingleRR[*dns.SOA](t, cfg, dns.TypeSOA, soaOwner)
	if soa.Ns != "ns1.example.com." || soa.Mbox != "hostmaster.example.com." || soa.Serial != 1 {
		t.Fatalf("unexpected SOA record: %+v", soa)
	}

	cert := requireSingleRR[*dns.CERT](t, cfg, dns.TypeCERT, certOwner)
	if cert.Type != 1 || cert.KeyTag != 123 || cert.Algorithm != 8 || cert.Certificate != "QUJDRA==" {
		t.Fatalf("unexpected CERT record: %+v", cert)
	}

	rp := requireSingleRR[*dns.RP](t, cfg, dns.TypeRP, rpOwner)
	if rp.Mbox != "hostmaster.example.com." || rp.Txt != "txt.example.com." {
		t.Fatalf("unexpected RP record: %+v", rp)
	}

	sshfp := requireSingleRR[*dns.SSHFP](t, cfg, dns.TypeSSHFP, sshfpOwner)
	if sshfp.Algorithm != 4 || sshfp.Type != 2 || sshfp.FingerPrint != "abcdef" {
		t.Fatalf("unexpected SSHFP record: %+v", sshfp)
	}
}

func TestLoadConfigFailsForInvalidSOA(t *testing.T) {
	_, err := loadConfig("testdata/config_invalid_soa")
	if err == nil {
		t.Fatal("expected loadConfig to fail for invalid SOA config")
	}
	if !strings.Contains(err.Error(), "(SOA) requires rname") {
		t.Fatalf("expected SOA rname validation error, got: %v", err)
	}
}

func writeConfigFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
	return dir
}

func TestLoadConfigFailsForInvalidConfigs(t *testing.T) {
	baseServer := `server {
	dns {
		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g" {
				weight = 10
				endpoint {
					addr    = "8.8.8.8"
					port    = 53
					percent = 100
				}
			}
    }

		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
  }

  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`

	tests := []struct {
		name       string
		recordsHCL string
		zonesHCL   string
		expectErr  string
	}{
		{
			name: "invalid-cert-missing-type",
			recordsHCL: `record "cert-bad" {
  type        = "CERT"
  ttl         = 3600
  algorithm   = 8
  certificate = "QUJDRA=="
}
`,
			zonesHCL: `zone "example.com." {
  records = ["cert-bad"]
}
`,
			expectErr: "(CERT) requires cert_type",
		},
		{
			name: "invalid-srv-no-target",
			recordsHCL: `record "_bad._tcp" {
  type = "SRV"
  port = 443
}
`,
			zonesHCL: `zone "example.com." {
  records = ["_bad._tcp"]
}
`,
			expectErr: "(SRV) requires at least one target block",
		},
		{
			name: "invalid-aaaa-ipv4",
			recordsHCL: `record "v6-bad" {
  type = "AAAA"
  ip6  = "192.168.1.5"
}
`,
			zonesHCL: `zone "example.com." {
  records = ["v6-bad"]
}
`,
			expectErr: "invalid IPv6 address",
		},
		{
			name: "zone-unknown-record-ref",
			recordsHCL: `record "a1" {
  type = "A"
  ip   = "192.168.1.10"
}
`,
			zonesHCL: `zone "example.com." {
  records = ["missing-id"]
}
`,
			expectErr: "references unknown record id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeConfigFiles(t, map[string]string{
				"server.hcl":  baseServer,
				"records.hcl": tt.recordsHCL,
				"zones.hcl":   tt.zonesHCL,
			})
			_, err := loadConfig(dir)
			if err == nil {
				t.Fatalf("expected loadConfig to fail for case %q", tt.name)
			}
			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error to contain %q, got: %v", tt.expectErr, err)
			}
		})
	}
}

func TestLoadConfigFailsForInvalidServerConfig(t *testing.T) {
	baseRecords := `record "r1" {
  type = "A"
  ip   = "192.168.1.10"
}
`
	baseZones := `zone "example.com." {
  records = ["r1"]
}
`

	tests := []struct {
		name      string
		serverHCL string
		expectErr string
	}{
		{
			name: "missing-keepalive-block",
			serverHCL: `server {
  dns {
		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
  }

  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`,
			expectErr: "Missing upstream block",
		},
		{
			name: "invalid-keepalive-interval",
			serverHCL: `server {
	dns {
		upstream {
			keepalive {
				interval_seconds = 0
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g" {
				endpoint {
					addr = "8.8.8.8"
				}
			}
    }

		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
  }

  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`,
			expectErr: "server.dns.upstream.keepalive.interval_seconds must be > 0",
		},
		{
			name: "no-resolved-upstreams",
			serverHCL: `server {
  dns {
		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g" {
			}
		}

		bind {
			addr = "127.0.0.1"
			port = 8053
			net  = "udp"
		}
  }

  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`,
			expectErr: "server.dns.upstream requires at least one group with at least one endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeConfigFiles(t, map[string]string{
				"server.hcl":  tt.serverHCL,
				"records.hcl": baseRecords,
				"zones.hcl":   baseZones,
			})
			_, err := loadConfig(dir)
			if err == nil {
				t.Fatalf("expected loadConfig to fail for case %q", tt.name)
			}
			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error to contain %q, got: %v", tt.expectErr, err)
			}
		})
	}
}

func TestValidateAllowsBindWithoutNet(t *testing.T) {
	serverHCL := `server {
  dns {
		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g" {
				endpoint {
					addr = "8.8.8.8"
				}
			}
		}

		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
  }

  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`
	recordsHCL := `record "r1" {
  type = "A"
  ip   = "192.168.1.10"
}
`
	zonesHCL := `zone "example.com." {
  records = ["r1"]
}
`

	dir := writeConfigFiles(t, map[string]string{
		"server.hcl":  serverHCL,
		"records.hcl": recordsHCL,
		"zones.hcl":   zonesHCL,
	})

	err := Validate(dir)
	if err != nil {
		t.Fatalf("expected Validate to succeed without bind net, got: %v", err)
	}
}

func TestLoadConfigFailsForConflictingUpstreamKeepalive(t *testing.T) {
	serverHCL := `server {
	dns {
		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g1" {
				keepalive {
					interval_seconds = 5
					window_seconds   = 15
					timeout_seconds  = 2
				}

				endpoint {
					addr = "8.8.8.8"
					port = 53
				}
			}

			group "g2" {
				keepalive {
					interval_seconds = 9
					window_seconds   = 30
					timeout_seconds  = 2
				}

				endpoint {
					addr = "8.8.8.8"
					port = 53
				}
			}
		}

		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
	}


  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`
	recordsHCL := `record "r1" {
	type = "A"
	ip   = "192.168.1.10"
}
`
	zonesHCL := `zone "example.com." {
	records = ["r1"]
}
`

	dir := writeConfigFiles(t, map[string]string{
		"server.hcl":  serverHCL,
		"records.hcl": recordsHCL,
		"zones.hcl":   zonesHCL,
	})

	_, err := loadConfig(dir)
	if err == nil {
		t.Fatal("expected loadConfig to fail for conflicting upstream keepalive")
	}
	if !strings.Contains(err.Error(), "conflicting keepalive settings") {
		t.Fatalf("expected conflicting keepalive error, got: %v", err)
	}
}

func TestLoadConfigAllowsSameUpstreamWithSameKeepalive(t *testing.T) {
	serverHCL := `server {
	dns {
		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g1" {
				keepalive {
					interval_seconds = 5
					window_seconds   = 15
					timeout_seconds  = 2
				}

				endpoint {
					addr = "8.8.8.8"
					port = 53
				}
			}

			group "g2" {
				keepalive {
					interval_seconds = 5
					window_seconds   = 15
					timeout_seconds  = 2
				}

				endpoint {
					addr = "8.8.8.8"
					port = 53
				}
			}
		}

		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
	}


  health {
    addr           = "127.0.0.1"
    port           = 8081
    net            = "tcp"
    readiness_path = "/readyz"
    liveness_path  = "/healthz"
    allow          = ["127.0.0.1", "::1"]
    deny           = []
  }

}
`
	recordsHCL := `record "r1" {
	type = "A"
	ip   = "192.168.1.10"
}
`
	zonesHCL := `zone "example.com." {
	records = ["r1"]
}
`

	dir := writeConfigFiles(t, map[string]string{
		"server.hcl":  serverHCL,
		"records.hcl": recordsHCL,
		"zones.hcl":   zonesHCL,
	})

	cfg, err := loadConfig(dir)
	if err != nil {
		t.Fatalf("expected loadConfig to succeed with identical keepalive, got: %v", err)
	}
	if len(cfg.UpstreamHealth) != 1 {
		t.Fatalf("expected deduped upstream health map size 1, got %d", len(cfg.UpstreamHealth))
	}
}

func TestValidateRejectsInvalidServiceACLs(t *testing.T) {
	baseRecords := `record "r1" {
	type = "A"
	ip   = "192.168.1.10"
}
`
	baseZones := `zone "example.com." {
	records = ["r1"]
}
`

	baseServer := `server {
	dns {
		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "g" {
				endpoint {
					addr = "8.8.8.8"
				}
			}
		}

		bind {
			addr = "127.0.0.1"
			port = 8053
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}
	}

	health {
		addr           = "127.0.0.1"
		port           = 8081
		net            = "tcp"
		readiness_path = "/readyz"
		liveness_path  = "/healthz"
		allow          = ["127.0.0.1", "::1"]
		deny           = []
	}

	%s
}
`

	tests := []struct {
		name      string
		block     string
		expectErr string
	}{
		{
			name: "invalid grpc allow",
			block: `grpc {
				addr = "127.0.0.1"
				port = 50051
				allow = ["not-an-ip"]
				deny  = []
			}`,
			expectErr: "invalid server grpc acl configuration",
		},
		{
			name: "invalid metrics deny",
			block: `metrics {
				addr = "127.0.0.1"
				port = 9090
				net  = "tcp"
				path = "/metrics"
				allow = []
				deny  = ["bad-ip"]
			}`,
			expectErr: "invalid server metrics acl configuration",
		},
		{
			name: "invalid acme allow",
			block: `acme {
				addr = "127.0.0.1"
				port = 9053
				allow = ["invalid"]
				deny  = []
			}`,
			expectErr: "invalid server acme acl configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverHCL := fmt.Sprintf(baseServer, tt.block)
			dir := writeConfigFiles(t, map[string]string{
				"server.hcl":  serverHCL,
				"records.hcl": baseRecords,
				"zones.hcl":   baseZones,
			})

			err := Validate(dir)
			if err == nil {
				t.Fatalf("expected Validate to fail for case %q", tt.name)
			}
			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error to contain %q, got: %v", tt.expectErr, err)
			}
		})
	}
}
