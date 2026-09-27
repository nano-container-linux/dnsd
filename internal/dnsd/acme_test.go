package dnsd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nano-container-linux/libdnsd"
)

// ---- resolveACMETTL -------------------------------------------------------

func TestResolveACMETTLDefault(t *testing.T) {
	if got := resolveACMETTL(nil); got != acmeDefaultTTL {
		t.Fatalf("expected %d, got %d", acmeDefaultTTL, got)
	}
}

func TestResolveACMETTLZero(t *testing.T) {
	cfg := &ACMEConfig{Addr: "127.0.0.1", Port: 9053, TTL: 0}
	if got := resolveACMETTL(cfg); got != acmeDefaultTTL {
		t.Fatalf("expected %d, got %d", acmeDefaultTTL, got)
	}
}

func TestResolveACMETTLCustom(t *testing.T) {
	cfg := &ACMEConfig{Addr: "127.0.0.1", Port: 9053, TTL: 120}
	if got := resolveACMETTL(cfg); got != 120 {
		t.Fatalf("expected 120, got %d", got)
	}
}

// ---- resolveACMEListen ----------------------------------------------------

func TestResolveACMEListenNilConfig(t *testing.T) {
	_, _, err := resolveACMEListen(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestResolveACMEListenMissingAddr(t *testing.T) {
	cfg := &ACMEConfig{Port: 9053}
	_, _, err := resolveACMEListen(cfg)
	if err == nil || !strings.Contains(err.Error(), "addr") {
		t.Fatalf("expected addr error, got: %v", err)
	}
}

func TestResolveACMEListenMissingPort(t *testing.T) {
	cfg := &ACMEConfig{Addr: "127.0.0.1"}
	_, _, err := resolveACMEListen(cfg)
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected port error, got: %v", err)
	}
}

func TestResolveACMEListenBadNet(t *testing.T) {
	cfg := &ACMEConfig{Addr: "127.0.0.1", Port: 9053, Net: "udp"}
	_, _, err := resolveACMEListen(cfg)
	if err == nil || !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("expected tcp error, got: %v", err)
	}
}

func TestResolveACMEListenOK(t *testing.T) {
	cfg := &ACMEConfig{Addr: "127.0.0.1", Port: 9053}
	addr, network, err := resolveACMEListen(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "127.0.0.1:9053" {
		t.Errorf("wrong addr: %s", addr)
	}
	if network != "tcp" {
		t.Errorf("wrong network: %s", network)
	}
}

// ---- isACMEChallengeName --------------------------------------------------

func TestIsACMEChallengeNameValid(t *testing.T) {
	cases := []string{
		"_acme-challenge.example.com.",
		"_acme-challenge.sub.example.com.",
	}
	for _, c := range cases {
		if !isACMEChallengeName(c) {
			t.Errorf("expected true for %q", c)
		}
	}
}

func TestIsACMEChallengeNameInvalid(t *testing.T) {
	cases := []string{
		"_acme-challenge.",
		"example.com.",
		"",
		"acme-challenge.example.com.",
	}
	for _, c := range cases {
		if isACMEChallengeName(c) {
			t.Errorf("expected false for %q", c)
		}
	}
}

func TestIsACMEChallengeNameCaseInsensitive(t *testing.T) {
	// normalizeName lowercases, so upper-case prefix should still be valid.
	if !isACMEChallengeName("_ACME-challenge.example.com.") {
		t.Error("expected true for uppercase _ACME-challenge (normalizeName lowercases)")
	}
}

// ---- presentACMETXT / cleanupACMETXT -------------------------------------

func newTestRuntime(zones []string) *RuntimeConfig {
	rt := &RuntimeConfig{
		Zones:      zones,
		ACMETXT:    map[string]map[string]struct{}{},
		ACMETokens: map[string]string{},
	}
	return rt
}

func TestACMEChallengeFQDN(t *testing.T) {
	if got := libdnsd.AcmeChallengeFQDN("example.com."); got != "_acme-challenge.example.com." {
		t.Fatalf("unexpected challenge fqdn: %s", got)
	}
	if got := libdnsd.AcmeChallengeFQDN("*.example.com."); got != "_acme-challenge.example.com." {
		t.Fatalf("unexpected wildcard challenge fqdn: %s", got)
	}
	if got := libdnsd.AcmeChallengeFQDN("_acme-challenge.example.com."); got != "_acme-challenge.example.com." {
		t.Fatalf("unexpected passthrough challenge fqdn: %s", got)
	}
}

func TestIsACMETokenAllowed(t *testing.T) {
	rt := newTestRuntime([]string{"example.com."})
	rt.ACMETokens["record-token"] = "_acme-challenge.example.com."

	if !rt.isACMETokenAllowed("record-token", "_acme-challenge.example.com.") {
		t.Fatal("record token should be allowed for matching fqdn")
	}
	if rt.isACMETokenAllowed("record-token", "_acme-challenge.other.example.com.") {
		t.Fatal("record token should not be allowed for non-matching fqdn")
	}
}

func TestLoadCreateRevokeACMETokens(t *testing.T) {
	dir := t.TempDir()
	rt := &RuntimeConfig{
		ConfigDir:  dir,
		ACMETokens: map[string]string{},
		ACMETXT:    map[string]map[string]struct{}{},
		Zones:      []string{"example.com."},
	}
	entry, err := rt.createACMEToken("example.com.")
	if err != nil {
		t.Fatalf("createACMEToken failed: %v", err)
	}
	if entry.FQDN != "_acme-challenge.example.com." {
		t.Fatalf("unexpected fqdn: %s", entry.FQDN)
	}
	path := filepath.Join(dir, "acme-tokens", entry.Token+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected persisted token file: %v", err)
	}
	loaded, err := loadACMETokens(dir)
	if err != nil {
		t.Fatalf("loadACMETokens failed: %v", err)
	}
	if loaded[entry.Token] != entry.FQDN {
		t.Fatalf("unexpected loaded token map: %#v", loaded)
	}
	if err := rt.revokeACMEToken(entry.Token); err != nil {
		t.Fatalf("revokeACMEToken failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected token file to be removed, got err=%v", err)
	}
}

func TestPresentAndCleanupACMETXT(t *testing.T) {
	rt := newTestRuntime([]string{"example.com."})

	rt.presentACMETXT("_acme-challenge.example.com.", "token1")
	rt.presentACMETXT("_acme-challenge.example.com.", "token2")

	rt.mu.RLock()
	vals := rt.ACMETXT["_acme-challenge.example.com."]
	rt.mu.RUnlock()
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d", len(vals))
	}

	rt.cleanupACMETXT("_acme-challenge.example.com.", "token1")
	rt.mu.RLock()
	vals = rt.ACMETXT["_acme-challenge.example.com."]
	rt.mu.RUnlock()
	if len(vals) != 1 {
		t.Fatalf("expected 1 value after cleanup, got %d", len(vals))
	}

	rt.cleanupACMETXT("_acme-challenge.example.com.", "token2")
	rt.mu.RLock()
	_, stillExists := rt.ACMETXT["_acme-challenge.example.com."]
	rt.mu.RUnlock()
	if stillExists {
		t.Fatal("expected owner entry removed when empty")
	}
}

func TestPresentACMETXTConcurrency(t *testing.T) {
	rt := newTestRuntime([]string{"example.com."})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rt.presentACMETXT("_acme-challenge.example.com.", string(rune('a'+n%26)))
		}(i)
	}
	wg.Wait()
}

// ---- hasZoneForName ------------------------------------------------------

func TestHasZoneForName(t *testing.T) {
	rt := newTestRuntime([]string{"example.com.", "lab.internal."})

	if !rt.hasZoneForName("_acme-challenge.example.com.") {
		t.Error("expected true for subdomain of example.com.")
	}
	if !rt.hasZoneForName("sub.lab.internal.") {
		t.Error("expected true for subdomain of lab.internal.")
	}
	if rt.hasZoneForName("other.org.") {
		t.Error("expected false for unserved zone")
	}
}

// ---- HTTP handler ---------------------------------------------------------

func acmeTestRuntime() *RuntimeConfig {
	return newTestRuntime([]string{"example.com."})
}

const testToken = "record-token"

func doACMERequest(t *testing.T, handler http.Handler, method, path, authHeader, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func presentBody(fqdn, value string) string {
	b, _ := json.Marshal(acmeUpdateRequest{FQDN: fqdn, Value: value})
	return string(b)
}

func TestACMEHandlerHealthz(t *testing.T) {
	h := newACMEHTTPHandler(acmeTestRuntime())
	rr := doACMERequest(t, h, http.MethodGet, "/healthz", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp acmeUpdateResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

func TestACMEHandlerHealthzWrongMethod(t *testing.T) {
	h := newACMEHTTPHandler(acmeTestRuntime())
	rr := doACMERequest(t, h, http.MethodPost, "/healthz", "", "")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestACMEHandlerPresentOK(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens[testToken] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.example.com.", "myvalue")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer "+testToken, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp acmeUpdateResponse
	if err := json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "presented" {
		t.Errorf("expected presented, got %s", resp.Status)
	}
	rt.mu.RLock()
	_, ok := rt.ACMETXT["_acme-challenge.example.com."]["myvalue"]
	rt.mu.RUnlock()
	if !ok {
		t.Error("expected value in ACMETXT after present")
	}
}

func TestACMEHandlerCleanupOK(t *testing.T) {
	rt := acmeTestRuntime()
	rt.presentACMETXT("_acme-challenge.example.com.", "myvalue")
	rt.ACMETokens[testToken] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.example.com.", "myvalue")
	rr := doACMERequest(t, h, http.MethodPost, "/cleanup", "Bearer "+testToken, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rt.mu.RLock()
	_, stillExists := rt.ACMETXT["_acme-challenge.example.com."]
	rt.mu.RUnlock()
	if stillExists {
		t.Error("expected value removed after cleanup")
	}
}

func TestACMEHandlerMissingToken(t *testing.T) {
	h := newACMEHTTPHandler(acmeTestRuntime())
	body := presentBody("_acme-challenge.example.com.", "v")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "", body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestACMEHandlerWrongToken(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens[testToken] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.example.com.", "v")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer wrongtoken", body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestACMEHandlerPerRecordTokenOK(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens["record-token"] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.example.com.", "v")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer record-token", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestACMEHandlerPerRecordTokenWrongFQDN(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens["record-token"] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.other.example.com.", "v")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer record-token", body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestACMEHandlerBadFQDN(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens[testToken] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("notacme.example.com.", "v")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer "+testToken, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestACMEHandlerEmptyValue(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens[testToken] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.example.com.", "")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer "+testToken, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestACMEHandlerZoneNotServed(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ACMETokens[testToken] = "_acme-challenge.example.com."
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.notserved.org.", "v")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer "+testToken, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestACMEHandlerWrongMethodOnPresent(t *testing.T) {
	h := newACMEHTTPHandler(acmeTestRuntime())
	rr := doACMERequest(t, h, http.MethodGet, "/present", "Bearer "+testToken, "")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestACMEHandlerWildcardTokenFromCaddy(t *testing.T) {
	rt := acmeTestRuntime()
	rt.ConfigDir = t.TempDir()
	entry, err := rt.createACMEToken("*.example.com.")
	if err != nil {
		t.Fatalf("createACMEToken wildcard failed: %v", err)
	}
	h := newACMEHTTPHandler(rt)
	body := presentBody("_acme-challenge.example.com.", "wildcard-value")
	rr := doACMERequest(t, h, http.MethodPost, "/present", "Bearer "+entry.Token, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for wildcard token, got %d: %s", rr.Code, rr.Body.String())
	}
}
