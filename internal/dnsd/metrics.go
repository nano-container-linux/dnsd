package dnsd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsRegisterOnce sync.Once

	dnsQuestionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnsd_dns_questions_total",
			Help: "Total DNS questions received by type.",
		},
		[]string{"qtype"},
	)

	dnsResponsesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnsd_dns_responses_total",
			Help: "Total DNS responses returned by rcode.",
		},
		[]string{"rcode"},
	)

	dynamicSubmissionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnsd_dynamic_submissions_total",
			Help: "Total dynamic DNS gRPC submissions by status.",
		},
		[]string{"status"},
	)
)

func registerMetrics() {
	metricsRegisterOnce.Do(func() {
		registerCollector(collectors.NewGoCollector())
		registerCollector(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		registerCollector(dnsQuestionsTotal)
		registerCollector(dnsResponsesTotal)
		registerCollector(dynamicSubmissionsTotal)
	})
}

func registerCollector(collector prometheus.Collector) {
	err := prometheus.Register(collector)
	if err == nil {
		return
	}
	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		return
	}
	panic(err)
}

func observeDNSQuestion(qtype uint16) {
	registerMetrics()
	label := dns.TypeToString[qtype]
	if label == "" {
		label = fmt.Sprintf("TYPE%d", qtype)
	}
	dnsQuestionsTotal.WithLabelValues(label).Inc()
}

func observeDNSResponse(rcode int) {
	registerMetrics()
	label := dns.RcodeToString[rcode]
	if label == "" {
		label = fmt.Sprintf("RCODE%d", rcode)
	}
	dnsResponsesTotal.WithLabelValues(label).Inc()
}

func observeDynamicSubmission(status string) {
	registerMetrics()
	dynamicSubmissionsTotal.WithLabelValues(status).Inc()
}

func resolveMetricsListen(cfg *MetricsConfig) (addr string, network string, path string, err error) {
	if cfg == nil {
		return "", "", "", fmt.Errorf("metrics config is nil")
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		return "", "", "", fmt.Errorf("metrics.addr is required")
	}
	if cfg.Port == 0 {
		return "", "", "", fmt.Errorf("metrics.port must be > 0")
	}

	network = strings.TrimSpace(cfg.Net)
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" {
		return "", "", "", fmt.Errorf("metrics.net must be tcp")
	}

	path = strings.TrimSpace(cfg.Path)
	if path == "" {
		path = "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	addr = net.JoinHostPort(strings.TrimSpace(cfg.Addr), fmt.Sprintf("%d", cfg.Port))
	return addr, network, path, nil
}

func startMetricsServer(cfg *MetricsConfig, errCh chan<- error) error {
	addr, network, path, err := resolveMetricsListen(cfg)
	if err != nil {
		return err
	}
	acl, err := parseRequiredACL(cfg.Allow, cfg.Deny, "server.metrics")
	if err != nil {
		return err
	}

	registerMetrics()
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, aclErr := acl.allowsRemote(addrFromRemoteAddrString(r.RemoteAddr))
		if aclErr != nil {
			logger.Error().Err(aclErr).Str("remote", r.RemoteAddr).Msg("metrics acl evaluation failed")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !allowed {
			logger.Warn().Str("remote", r.RemoteAddr).Msg("metrics request refused by acl")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		promhttp.Handler().ServeHTTP(w, r)
	}))
	server := &http.Server{Addr: addr, Handler: mux}

	logger.Info().
		Str("addr", addr).
		Str("net", network).
		Str("path", path).
		Msg("starting prometheus metrics listener")

	go func() {
		errCh <- server.ListenAndServe()
	}()
	return nil
}
