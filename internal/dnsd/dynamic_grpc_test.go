package dnsd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestVerifyDynamicRequest_WithAuthorizedKey(t *testing.T) {
	pubRaw, privRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	privSigner, err := ssh.NewSignerFromKey(privRaw)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(pubRaw)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	authFile := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(authFile, ssh.MarshalAuthorizedKey(pubKey), 0o600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := privSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(pubKey)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	if err := verifyDynamicRequest(req, GRPCConfig{AuthorizedKeysFile: authFile}); err != nil {
		t.Fatalf("verifyDynamicRequest returned error: %v", err)
	}
}

func TestVerifyDynamicRequest_WithUserCertificateAndAuthorizedEmail(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("failed to create ca signer: %v", err)
	}

	email := "alice@example.com"
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign user cert: %v", err)
	}

	caFile := filepath.Join(t.TempDir(), "trusted_user_ca_keys")
	if err := os.WriteFile(caFile, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("failed to write trusted_user_ca_keys: %v", err)
	}
	emailsFile := filepath.Join(filepath.Dir(caFile), "authorized_emails")
	if err := os.WriteFile(emailsFile, []byte(email+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write authorized_emails: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := userSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(cert)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	cfg := GRPCConfig{
		TrustedUserCAKeysFile: caFile,
		AuthorizedEmailsFile:  emailsFile,
	}

	if err := verifyDynamicRequest(req, cfg); err != nil {
		t.Fatalf("verifyDynamicRequest with certificate returned error: %v", err)
	}
}

func TestVerifyDynamicRequest_WithUserCertificateAndAuthorizedDomain(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("failed to create ca signer: %v", err)
	}

	email := "bob@example.com"
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          2,
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign user cert: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "trusted_user_ca_keys")
	if err := os.WriteFile(caFile, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("failed to write trusted_user_ca_keys: %v", err)
	}
	emailsFile := filepath.Join(tmpDir, "authorized_emails")
	if err := os.WriteFile(emailsFile, []byte("@example.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write authorized_emails: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := userSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(cert)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	cfg := GRPCConfig{
		TrustedUserCAKeysFile: caFile,
		AuthorizedEmailsFile:  emailsFile,
	}

	if err := verifyDynamicRequest(req, cfg); err != nil {
		t.Fatalf("verifyDynamicRequest with authorized domain returned error: %v", err)
	}
}

func TestVerifyDynamicRequest_WithUserCertificateAndAuthorizedDomainGroup(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("failed to create ca signer: %v", err)
	}

	email := "carol@example.com"
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          3,
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"groups": "devops,platform",
		}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign user cert: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "trusted_user_ca_keys")
	if err := os.WriteFile(caFile, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("failed to write trusted_user_ca_keys: %v", err)
	}
	emailsFile := filepath.Join(tmpDir, "authorized_emails")
	if err := os.WriteFile(emailsFile, []byte("@example.com:devops&&platform\n"), 0o600); err != nil {
		t.Fatalf("failed to write authorized_emails: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := userSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(cert)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	cfg := GRPCConfig{
		TrustedUserCAKeysFile: caFile,
		AuthorizedEmailsFile:  emailsFile,
	}

	if err := verifyDynamicRequest(req, cfg); err != nil {
		t.Fatalf("verifyDynamicRequest with authorized domain group returned error: %v", err)
	}
}

func TestVerifyDynamicRequest_WithUserCertificateAndAuthorizedDomainGroupOr(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("failed to create ca signer: %v", err)
	}

	email := "dave@example.com"
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          4,
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"groups": "platform",
		}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign user cert: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "trusted_user_ca_keys")
	if err := os.WriteFile(caFile, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("failed to write trusted_user_ca_keys: %v", err)
	}
	emailsFile := filepath.Join(tmpDir, "authorized_emails")
	if err := os.WriteFile(emailsFile, []byte("@example.com:devops||platform\n"), 0o600); err != nil {
		t.Fatalf("failed to write authorized_emails: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := userSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(cert)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	cfg := GRPCConfig{
		TrustedUserCAKeysFile: caFile,
		AuthorizedEmailsFile:  emailsFile,
	}

	if err := verifyDynamicRequest(req, cfg); err != nil {
		t.Fatalf("verifyDynamicRequest with domain OR group rule returned error: %v", err)
	}
}

func TestVerifyDynamicRequest_WithUserCertificateAndAuthorizedDomainGroupAndDenied(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("failed to create ca signer: %v", err)
	}

	email := "erin@example.com"
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          5,
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"groups": "devops",
		}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign user cert: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "trusted_user_ca_keys")
	if err := os.WriteFile(caFile, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("failed to write trusted_user_ca_keys: %v", err)
	}
	emailsFile := filepath.Join(tmpDir, "authorized_emails")
	if err := os.WriteFile(emailsFile, []byte("@example.com:devops&&platform\n"), 0o600); err != nil {
		t.Fatalf("failed to write authorized_emails: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := userSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(cert)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	cfg := GRPCConfig{
		TrustedUserCAKeysFile: caFile,
		AuthorizedEmailsFile:  emailsFile,
	}

	err = verifyDynamicRequest(req, cfg)
	if err == nil {
		t.Fatal("expected verifyDynamicRequest to reject missing required group in AND expression")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected authorization error, got: %v", err)
	}
}

func TestVerifyDynamicRequest_WithUserCertificateAndAuthorizedDomainGroupOrDenied(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("failed to create user signer: %v", err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("failed to create ca signer: %v", err)
	}

	email := "frank@example.com"
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          6,
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"groups": "security",
		}},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign user cert: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "trusted_user_ca_keys")
	if err := os.WriteFile(caFile, ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("failed to write trusted_user_ca_keys: %v", err)
	}
	emailsFile := filepath.Join(tmpDir, "authorized_emails")
	if err := os.WriteFile(emailsFile, []byte("@example.com:devops||platform\n"), 0o600); err != nil {
		t.Fatalf("failed to write authorized_emails: %v", err)
	}

	payload := `record "web" { type = "A" ip = "192.0.2.1" }
zone "example.com." { records = ["web"] }`
	sig, err := userSigner.Sign(rand.Reader, []byte(payload))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	req := DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  string(ssh.MarshalAuthorizedKey(cert)),
		Signature:  base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}

	cfg := GRPCConfig{
		TrustedUserCAKeysFile: caFile,
		AuthorizedEmailsFile:  emailsFile,
	}

	err = verifyDynamicRequest(req, cfg)
	if err == nil {
		t.Fatal("expected verifyDynamicRequest to reject when no OR group matches")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected authorization error, got: %v", err)
	}
}

func TestParseAllowlistEntry_InvalidExpressions(t *testing.T) {
	tests := []string{
		"@example.com:devops||",
		"@example.com:&&platform",
		"@example.com:devops&&",
		"@example.com:devops|||platform",
		"@example.com:devops&&||platform",
		"@example.com:",
		"example.com",
		"@example.com:devops&&pla/tform",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, _, _, err := parseAllowlistEntry(input)
			if err == nil {
				t.Fatalf("expected parseAllowlistEntry(%q) to fail", input)
			}
		})
	}
}
