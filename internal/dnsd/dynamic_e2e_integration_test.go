package dnsd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve udp port: %v", err)
	}
	defer pc.Close()
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("failed to resolve udp addr")
	}
	return uint16(addr.Port)
}

func reserveTCPPort(t *testing.T) uint16 {
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

func TestDynamicSubmitE2E_GRPCToDNS(t *testing.T) {
	dnsPort := reserveUDPPort(t)
	grpcPort := reserveTCPPort(t)
	healthPort := reserveTCPPort(t)
	tmpDir := t.TempDir()

	pubRaw, privRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privRaw)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(pubRaw)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	authorizedKeysPath := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(authorizedKeysPath, ssh.MarshalAuthorizedKey(pubKey), 0o600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	serverHCL := fmt.Sprintf(`server {
  dns {
		bind {
			addr = "127.0.0.1"
			port = %d
			query {
				allow = ["127.0.0.1"]
				deny  = []
			}
			transfer {
				allow = ["127.0.0.1"]
				deny  = []
			}
		}

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
  }

  grpc {
    addr                 = "127.0.0.1"
    port                 = %d
    net                  = "tcp"
    authorized_keys_file = %q
		allow                = ["127.0.0.1", "::1"]
		deny                 = []
  }

	health {
		addr           = "127.0.0.1"
		port           = %d
		net            = "tcp"
		readiness_path = "/readyz"
		liveness_path  = "/healthz"
		allow          = ["127.0.0.1", "::1"]
		deny           = []
	}
}
`, dnsPort, grpcPort, authorizedKeysPath, healthPort)
	recordsHCL := `record "bootstrap" {
  type = "A"
  ip   = "192.0.2.1"
}
`
	zonesHCL := `zone "example.com." {
  records = ["bootstrap"]
}
`

	if err := os.WriteFile(filepath.Join(tmpDir, "server.hcl"), []byte(serverHCL), 0o644); err != nil {
		t.Fatalf("failed to write server.hcl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "records.hcl"), []byte(recordsHCL), 0o644); err != nil {
		t.Fatalf("failed to write records.hcl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "zones.hcl"), []byte(zonesHCL), 0o644); err != nil {
		t.Fatalf("failed to write zones.hcl: %v", err)
	}

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(tmpDir)
	}()

	dynamicPayload := `record "dyn" {
  type = "A"
  ip   = "192.0.2.99"
}

zone "example.com." {
  records = ["dyn"]
}
`

	sig, err := signer.Sign(rand.Reader, []byte(dynamicPayload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	req := DynamicSubmitRequest{
		PayloadHCL: dynamicPayload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(pubKey)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	grpcTarget := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", grpcPort))
	var submitResp *DynamicSubmitResponse
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-runErr:
			t.Fatalf("server exited before grpc submit: %v", err)
		default:
		}

		submitResp, err = submitDynamicOverGRPC(grpcTarget, req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("grpc submit did not succeed before timeout: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if submitResp.ID == "" {
		t.Fatal("expected non-empty dynamic submission id")
	}
	if _, err := os.Stat(submitResp.Path); err != nil {
		t.Fatalf("expected dynamic persistence file to exist: %v", err)
	}

	dnsClient := &dns.Client{Timeout: 2 * time.Second}
	dnsMsg := new(dns.Msg)
	dnsMsg.SetQuestion("dyn.example.com.", dns.TypeA)
	dnsAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", dnsPort))

	deadline = time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-runErr:
			t.Fatalf("server exited before dns verification: %v", err)
		default:
		}

		resp, _, err := dnsClient.Exchange(dnsMsg, dnsAddr)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			a, ok := resp.Answer[0].(*dns.A)
			if !ok {
				t.Fatalf("expected A answer, got %T", resp.Answer[0])
			}
			if got := a.A.String(); got != "192.0.2.99" {
				t.Fatalf("expected 192.0.2.99, got %s", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dns response did not include dynamic answer before timeout (last err=%v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
