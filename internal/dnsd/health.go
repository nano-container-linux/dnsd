package dnsd

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func resolveHealthListen(cfg *HealthConfig) (addr string, network string, readinessPath string, livenessPath string, err error) {
	if cfg == nil {
		return "", "", "", "", fmt.Errorf("health config is nil")
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		return "", "", "", "", fmt.Errorf("health.addr is required")
	}
	if cfg.Port == 0 {
		return "", "", "", "", fmt.Errorf("health.port must be > 0")
	}

	network = strings.TrimSpace(cfg.Net)
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" {
		return "", "", "", "", fmt.Errorf("health.net must be tcp")
	}

	readinessPath = strings.TrimSpace(cfg.ReadinessPath)
	if readinessPath == "" {
		readinessPath = "/readyz"
	}
	if !strings.HasPrefix(readinessPath, "/") {
		readinessPath = "/" + readinessPath
	}

	livenessPath = strings.TrimSpace(cfg.LivenessPath)
	if livenessPath == "" {
		livenessPath = "/healthz"
	}
	if !strings.HasPrefix(livenessPath, "/") {
		livenessPath = "/" + livenessPath
	}

	addr = net.JoinHostPort(strings.TrimSpace(cfg.Addr), fmt.Sprintf("%d", cfg.Port))
	return addr, network, readinessPath, livenessPath, nil
}

func newHealthHTTPHandler(runtime *RuntimeConfig, readinessPath, livenessPath string, acl bindACLRuntime) http.Handler {
	mux := http.NewServeMux()

	checkACL := func(w http.ResponseWriter, r *http.Request) bool {
		allowed, err := acl.allowsRemote(addrFromRemoteAddrString(r.RemoteAddr))
		if err != nil {
			logger.Error().Err(err).Str("remote", r.RemoteAddr).Msg("health acl evaluation failed")
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
		if !allowed {
			logger.Warn().Str("remote", r.RemoteAddr).Msg("health request refused by acl")
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
		return true
	}

	mux.HandleFunc(readinessPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkACL(w, r) {
			return
		}

		ready := true
		runtime.mu.RLock()
		for addr := range runtime.UpstreamHealth {
			if !runtime.isUpstreamAvailable(addr) {
				ready = false
				break
			}
		}
		runtime.mu.RUnlock()

		if !ready {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc(livenessPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkACL(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}

func startHealthServer(runtime *RuntimeConfig, cfg *HealthConfig, errCh chan<- error) error {
	addr, network, readinessPath, livenessPath, err := resolveHealthListen(cfg)
	if err != nil {
		return err
	}
	acl, err := parseRequiredACL(cfg.Allow, cfg.Deny, "server.health")
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:    addr,
		Handler: newHealthHTTPHandler(runtime, readinessPath, livenessPath, acl),
	}

	logger.Info().
		Str("addr", addr).
		Str("net", network).
		Str("readiness_path", readinessPath).
		Str("liveness_path", livenessPath).
		Msg("starting health listener")

	go func() {
		errCh <- server.ListenAndServe()
	}()
	return nil
}
