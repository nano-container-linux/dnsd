package dnsd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/nano-container-linux/libdnsd"
	"github.com/rs/zerolog/log"
)

const acmeDefaultTTL uint32 = 60

// ACMETokenEntry is persisted on disk for each per-record token.
type ACMETokenEntry struct {
	Token string `json:"token"`
	FQDN  string `json:"fqdn"` // canonical _acme-challenge.xxx. name
}

type acmeUpdateRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

type acmeUpdateResponse struct {
	Status string `json:"status"`
	Owner  string `json:"owner,omitempty"`
	Value  string `json:"value,omitempty"`
}

func resolveACMETTL(cfg *ACMEConfig) uint32 {
	if cfg == nil || cfg.TTL == 0 {
		return acmeDefaultTTL
	}
	return cfg.TTL
}

func resolveACMEListen(cfg *ACMEConfig) (addr string, network string, err error) {
	if cfg == nil {
		return "", "", fmt.Errorf("acme config is nil")
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		return "", "", fmt.Errorf("acme.addr is required")
	}
	if cfg.Port == 0 {
		return "", "", fmt.Errorf("acme.port must be > 0")
	}
	network = strings.TrimSpace(cfg.Net)
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" {
		return "", "", fmt.Errorf("acme.net must be tcp")
	}
	addr = net.JoinHostPort(strings.TrimSpace(cfg.Addr), fmt.Sprintf("%d", cfg.Port))
	return addr, network, nil
}

// acmeChallengeFQDN is now libdnsd.AcmeChallengeFQDN

// isACMEChallengeName returns true if name is a valid _acme-challenge. prefixed FQDN.
func isACMEChallengeName(name string) bool {
	norm := libdnsd.NormalizeName(name)
	return strings.HasPrefix(norm, "_acme-challenge.") && norm != "_acme-challenge."
}

// hasZoneForName returns true if the runtime serves a zone that is a parent of name.
func (cfg *RuntimeConfig) hasZoneForName(name string) bool {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	norm := libdnsd.NormalizeName(name)
	for _, zone := range cfg.Zones {
		if dns.IsSubDomain(zone, norm) {
			return true
		}
	}
	return false
}

// isACMETokenAllowed returns true if the given bearer token is authorized
// to present/cleanup TXT records for ownerFQDN.
// Per-record tokens in cfg.ACMETokens are restricted to a single FQDN.
func (cfg *RuntimeConfig) isACMETokenAllowed(requestToken, ownerFQDN string) bool {
	if requestToken == "" {
		return false
	}
	cfg.mu.RLock()
	allowedFQDN, ok := cfg.ACMETokens[requestToken]
	cfg.mu.RUnlock()
	if !ok {
		return false
	}
	return allowedFQDN == ownerFQDN
}

// presentACMETXT stores a TXT challenge value for owner.
func (cfg *RuntimeConfig) presentACMETXT(owner string, value string) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	if _, ok := cfg.ACMETXT[owner]; !ok {
		cfg.ACMETXT[owner] = map[string]struct{}{}
	}
	cfg.ACMETXT[owner][value] = struct{}{}
}

// cleanupACMETXT removes a TXT challenge value for owner.
func (cfg *RuntimeConfig) cleanupACMETXT(owner string, value string) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	values, ok := cfg.ACMETXT[owner]
	if !ok {
		return
	}
	delete(values, value)
	if len(values) == 0 {
		delete(cfg.ACMETXT, owner)
	}
}

// --- ACME token persistence ------------------------------------------------

func acmeTokensDir(configDir string) string {
	return filepath.Join(configDir, "acme-tokens")
}

// generateACMEToken generates a cryptographically random 32-byte hex token.
func generateACMEToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// loadACMETokens reads all persisted ACME token entries from disk.
// Returns a map of token to canonical _acme-challenge FQDN.
func loadACMETokens(configDir string) (map[string]string, error) {
	dir := acmeTokensDir(configDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("failed to read acme-tokens dir %s: %w", dir, err)
	}
	tokens := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read acme token file %s: %w", path, err)
		}
		var tok ACMETokenEntry
		if err := json.Unmarshal(data, &tok); err != nil {
			return nil, fmt.Errorf("failed to parse acme token file %s: %w", path, err)
		}
		if tok.Token != "" && tok.FQDN != "" {
			tokens[tok.Token] = tok.FQDN
		}
	}
	return tokens, nil
}

// createACMEToken generates a new token for fqdn, persists it, and registers it in the runtime.
// fqdn may be a base domain ("example.com.") or a _acme-challenge.xxx. name.
func (cfg *RuntimeConfig) createACMEToken(fqdn string) (*ACMETokenEntry, error) {
	challengeFQDN := libdnsd.AcmeChallengeFQDN(fqdn)
	if challengeFQDN == "_acme-challenge." {
		return nil, fmt.Errorf("invalid fqdn: %q", fqdn)
	}
	tok, err := generateACMEToken()
	if err != nil {
		return nil, err
	}
	entry := &ACMETokenEntry{Token: tok, FQDN: challengeFQDN}
	if err := persistACMEToken(cfg.ConfigDir, entry); err != nil {
		return nil, err
	}
	cfg.mu.Lock()
	cfg.ACMETokens[tok] = challengeFQDN
	cfg.mu.Unlock()
	return entry, nil
}

// revokeACMEToken removes a token from runtime and disk.
func (cfg *RuntimeConfig) revokeACMEToken(token string) error {
	cfg.mu.Lock()
	_, ok := cfg.ACMETokens[token]
	if ok {
		delete(cfg.ACMETokens, token)
	}
	cfg.mu.Unlock()
	if !ok {
		return fmt.Errorf("token not found")
	}
	return deleteACMEToken(cfg.ConfigDir, token)
}

// listACMETokens returns a snapshot of all per-record tokens.
func (cfg *RuntimeConfig) listACMETokens() []ACMETokenEntry {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	out := make([]ACMETokenEntry, 0, len(cfg.ACMETokens))
	for tok, fqdn := range cfg.ACMETokens {
		out = append(out, ACMETokenEntry{Token: tok, FQDN: fqdn})
	}
	return out
}

func persistACMEToken(configDir string, entry *ACMETokenEntry) error {
	dir := acmeTokensDir(configDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create acme-tokens dir %s: %w", dir, err)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal acme token: %w", err)
	}
	filename := filepath.Join(dir, entry.Token+".json")
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		return fmt.Errorf("failed to write acme token file %s: %w", filename, err)
	}
	return nil
}

func deleteACMEToken(configDir string, token string) error {
	filename := filepath.Join(acmeTokensDir(configDir), token+".json")
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete acme token file %s: %w", filename, err)
	}
	return nil
}

// --- HTTP handler ----------------------------------------------------------

func writeACMEJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newACMEHTTPHandler(runtime *RuntimeConfig) http.Handler {
	mux := http.NewServeMux()

	extractToken := func(r *http.Request) string {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			return ""
		}
		return strings.TrimSpace(strings.TrimPrefix(header, prefix))
	}

	updateHandler := func(isCleanup bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				writeACMEJSON(w, http.StatusMethodNotAllowed, acmeUpdateResponse{Status: "method_not_allowed"})
				return
			}
			requestToken := extractToken(r)
			if requestToken == "" {
				writeACMEJSON(w, http.StatusUnauthorized, acmeUpdateResponse{Status: "unauthorized"})
				return
			}
			var req acmeUpdateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeACMEJSON(w, http.StatusBadRequest, acmeUpdateResponse{Status: "invalid_json"})
				return
			}
			owner := normalizeName(req.FQDN)
			value := strings.TrimSpace(req.Value)
			if !isACMEChallengeName(owner) {
				writeACMEJSON(w, http.StatusBadRequest, acmeUpdateResponse{Status: "invalid_fqdn"})
				return
			}
			if value == "" {
				writeACMEJSON(w, http.StatusBadRequest, acmeUpdateResponse{Status: "invalid_value"})
				return
			}
			if !runtime.hasZoneForName(owner) {
				writeACMEJSON(w, http.StatusBadRequest, acmeUpdateResponse{Status: "zone_not_served"})
				return
			}
			if !runtime.isACMETokenAllowed(requestToken, owner) {
				writeACMEJSON(w, http.StatusForbidden, acmeUpdateResponse{Status: "forbidden"})
				return
			}
			if isCleanup {
				runtime.cleanupACMETXT(owner, value)
				log.Info().Str("owner", owner).Msg("acme dns cleanup")
				writeACMEJSON(w, http.StatusOK, acmeUpdateResponse{Status: "cleaned", Owner: owner, Value: value})
				return
			}
			runtime.presentACMETXT(owner, value)
			log.Info().Str("owner", owner).Msg("acme dns present")
			writeACMEJSON(w, http.StatusOK, acmeUpdateResponse{Status: "presented", Owner: owner, Value: value})
		}
	}

	mux.Handle("/present", updateHandler(false))
	mux.Handle("/cleanup", updateHandler(true))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeACMEJSON(w, http.StatusMethodNotAllowed, acmeUpdateResponse{Status: "method_not_allowed"})
			return
		}
		writeACMEJSON(w, http.StatusOK, acmeUpdateResponse{Status: "ok"})
	})

	return mux
}

func startACMEServer(runtime *RuntimeConfig, cfg *ACMEConfig, errCh chan<- error) error {
	addr, network, err := resolveACMEListen(cfg)
	if err != nil {
		return err
	}
	acl, err := parseRequiredACL(cfg.Allow, cfg.Deny, "server.acme")
	if err != nil {
		return err
	}
	logger := log.With().Str("addr", addr).Str("net", network).Logger()
	logger.Info().Msg("starting acme dns listener")
	baseHandler := newACMEHTTPHandler(runtime)
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, aclErr := acl.allowsRemote(addrFromRemoteAddrString(r.RemoteAddr))
			if aclErr != nil {
				logger.Error().Err(aclErr).Str("remote", r.RemoteAddr).Msg("acme acl evaluation failed")
				writeACMEJSON(w, http.StatusForbidden, acmeUpdateResponse{Status: "forbidden"})
				return
			}
			if !allowed {
				logger.Warn().Str("remote", r.RemoteAddr).Msg("acme request refused by acl")
				writeACMEJSON(w, http.StatusForbidden, acmeUpdateResponse{Status: "forbidden"})
				return
			}
			baseHandler.ServeHTTP(w, r)
		}),
	}
	go func() {
		errCh <- server.ListenAndServe()
	}()
	return nil
}
