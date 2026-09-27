package dnsd

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/zclconf/go-cty/cty"
)

var logger = zerolog.New(os.Stdout).With().Timestamp().Str("component", "dnsd").Logger()

type Config struct {
	Server  ServerConfig   `hcl:"server,block"`
	Records []RecordConfig `hcl:"record,block"`
	Zones   []ZoneConfig   `hcl:"zone,block"`
}

type PartialConfig struct {
	Servers []ServerConfig `hcl:"server,block"`
	Records []RecordConfig `hcl:"record,block"`
	Zones   []ZoneConfig   `hcl:"zone,block"`
}

type ServerConfig struct {
	DNS     DNSConfig      `hcl:"dns,block"`
	GRPC    *GRPCConfig    `hcl:"grpc,block"`
	ACME    *ACMEConfig    `hcl:"acme,block"`
	Metrics *MetricsConfig `hcl:"metrics,block"`
	Health  HealthConfig   `hcl:"health,block"`
}

type DNSConfig struct {
	Binds    []BindConfig      `hcl:"bind,block"`
	Upstream DNSUpstreamConfig `hcl:"upstream,block"`
}

type DNSUpstreamConfig struct {
	Keepalive KeepaliveConfig          `hcl:"keepalive,block"`
	Groups    []DNSUpstreamGroupConfig `hcl:"group,block"`
}

type MetricsConfig struct {
	Addr  string   `hcl:"addr"`
	Port  uint16   `hcl:"port"`
	Net   string   `hcl:"net,optional"`
	Path  string   `hcl:"path,optional"`
	Allow []string `hcl:"allow"`
	Deny  []string `hcl:"deny"`
}

type GRPCConfig struct {
	Addr                  string   `hcl:"addr"`
	Port                  uint16   `hcl:"port"`
	Net                   string   `hcl:"net,optional"`
	AuthorizedKeysFile    string   `hcl:"authorized_keys_file,optional"`
	TrustedUserCAKeysFile string   `hcl:"trusted_user_ca_keys_file,optional"`
	AuthorizedEmailsFile  string   `hcl:"authorized_emails_file,optional"`
	Allow                 []string `hcl:"allow"`
	Deny                  []string `hcl:"deny"`
}

type ACMEConfig struct {
	Addr  string   `hcl:"addr"`
	Port  uint16   `hcl:"port"`
	Net   string   `hcl:"net,optional"`
	TTL   uint32   `hcl:"ttl,optional"`
	Allow []string `hcl:"allow"`
	Deny  []string `hcl:"deny"`
}

type HealthConfig struct {
	Addr          string   `hcl:"addr"`
	Port          uint16   `hcl:"port"`
	Net           string   `hcl:"net,optional"`
	ReadinessPath string   `hcl:"readiness_path,optional"`
	LivenessPath  string   `hcl:"liveness_path,optional"`
	Allow         []string `hcl:"allow"`
	Deny          []string `hcl:"deny"`
}

type KeepaliveConfig struct {
	IntervalSeconds uint32 `hcl:"interval_seconds"`
	WindowSeconds   uint32 `hcl:"window_seconds"`
	TimeoutSeconds  uint32 `hcl:"timeout_seconds"`
}

type KeepaliveOverrideConfig struct {
	IntervalSeconds uint32 `hcl:"interval_seconds,optional"`
	WindowSeconds   uint32 `hcl:"window_seconds,optional"`
	TimeoutSeconds  uint32 `hcl:"timeout_seconds,optional"`
}

// UpstreamGroupConfig groups upstreams with a priority weight.
// Lower weight = higher priority. Within a group, upstreams are
// selected randomly according to their percent attribute.
type DNSUpstreamGroupConfig struct {
	Name      string                   `hcl:",label"`
	Domains   []string                 `hcl:"domains,optional"`
	Weight    uint16                   `hcl:"weight,optional"`
	Keepalive *KeepaliveOverrideConfig `hcl:"keepalive,block"`
	Endpoints []DNSEndpointConfig      `hcl:"endpoint,block"`
}

type DNSEndpointConfig struct {
	Addr           string                   `hcl:"addr"`
	SystemResolver bool                     `hcl:"system_resolver,optional"`
	Port           uint16                   `hcl:"port,optional"`
	Percent        uint16                   `hcl:"percent,optional"`
	Description    string                   `hcl:"description,optional"`
	Keepalive      *KeepaliveOverrideConfig `hcl:"keepalive,block"`
}

func resolveSystemResolverAddrs(portOverride uint16) ([]string, error) {
	clientCfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to parse /etc/resolv.conf for system resolver upstream: %w", err)
	}
	return resolverAddrsFromClientConfig(clientCfg, portOverride)
}

func resolverAddrsFromClientConfig(clientCfg *dns.ClientConfig, portOverride uint16) ([]string, error) {
	if clientCfg == nil {
		return nil, fmt.Errorf("system resolver config is nil")
	}

	port := strings.TrimSpace(clientCfg.Port)
	if port == "" {
		port = "53"
	}
	if portOverride > 0 {
		port = strconv.Itoa(int(portOverride))
	}

	out := make([]string, 0, len(clientCfg.Servers))
	for _, server := range clientCfg.Servers {
		host := strings.TrimSpace(server)
		if host == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(host); err == nil {
			out = append(out, host)
			continue
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no resolver nameservers found in system resolver configuration")
	}
	return out, nil
}

func splitPercent(total uint16, count int) []uint16 {
	if count <= 0 {
		return nil
	}
	out := make([]uint16, count)
	if total == 0 {
		return out
	}
	base := total / uint16(count)
	rest := int(total % uint16(count))
	for i := 0; i < count; i++ {
		out[i] = base
		if i < rest {
			out[i]++
		}
	}
	return out
}

// upstreamEntry is a resolved upstream address used at runtime.
type upstreamEntry struct {
	addr        string
	description string
	keepalive   KeepaliveRuntimeConfig
}

// upstreamGroup is a resolved group of upstreams used at runtime.
type resolvedUpstreamGroup struct {
	name     string
	domains  []string
	entries  []upstreamEntry
	percents []uint16
	total    uint16
}

type upstreamHealth struct {
	mu        sync.RWMutex
	down      bool
	downUntil time.Time
}

type BindConfig struct {
	Addr     string            `hcl:"addr"`
	Port     uint16            `hcl:"port"`
	Net      string            `hcl:"net,optional"`
	Query    *BindAccessConfig `hcl:"query,block"`
	Transfer *BindAccessConfig `hcl:"transfer,block"`
}

type BindAccessConfig struct {
	Allow []string `hcl:"allow,optional"`
	Deny  []string `hcl:"deny,optional"`
}

type bindACLRuntime struct {
	allow []netip.Prefix
	deny  []netip.Prefix
}

type bindPolicyRuntime struct {
	query    bindACLRuntime
	transfer bindACLRuntime
}

type ListenBind struct {
	Addr   string
	Net    string
	Policy bindPolicyRuntime
}

type RecordConfig struct {
	ID       string            `hcl:",label"`
	Type     string            `hcl:"type"`
	TTL      uint32            `hcl:"ttl,optional"`
	IP       string            `hcl:"ip,optional"`
	IP6      string            `hcl:"ip6,optional"`
	CNAME    string            `hcl:"cname,optional"`
	PTR      string            `hcl:"ptr,optional"`
	NS       string            `hcl:"ns,optional"`
	Exchange string            `hcl:"exchange,optional"`
	Text     string            `hcl:"text,optional"`
	Texts    []string          `hcl:"texts,optional"`
	MName    string            `hcl:"mname,optional"`
	RName    string            `hcl:"rname,optional"`
	Serial   uint32            `hcl:"serial,optional"`
	Refresh  uint32            `hcl:"refresh,optional"`
	Retry    uint32            `hcl:"retry,optional"`
	Expire   uint32            `hcl:"expire,optional"`
	Minimum  uint32            `hcl:"minimum,optional"`
	CertType uint16            `hcl:"cert_type,optional"`
	KeyTag   uint16            `hcl:"key_tag,optional"`
	Algo     uint8             `hcl:"algorithm,optional"`
	Cert     string            `hcl:"certificate,optional"`
	Mbox     string            `hcl:"mbox,optional"`
	TxtDName string            `hcl:"txtdname,optional"`
	FPType   uint8             `hcl:"fp_type,optional"`
	FP       string            `hcl:"fingerprint,optional"`
	Priority uint16            `hcl:"priority,optional"`
	Weight   uint16            `hcl:"weight,optional"`
	Port     uint16            `hcl:"port,optional"`
	Targets  []SRVTargetConfig `hcl:"target,block"`
}

type SRVTargetConfig struct {
	Name     string  `hcl:"name"`
	Port     *uint16 `hcl:"port,optional"`
	Priority *uint16 `hcl:"priority,optional"`
	Weight   *uint16 `hcl:"weight,optional"`
}

type ZoneConfig struct {
	Name    string   `hcl:",label"`
	Records []string `hcl:"records"`
}

type RuntimeConfig struct {
	mu             sync.RWMutex
	Server         ServerConfig
	UpstreamGroups []resolvedUpstreamGroup
	UpstreamHealth map[string]*upstreamHealth
	Zones          []string
	Answers        map[uint16]map[string][]dns.RR
	ACMETXT        map[string]map[string]struct{}
	ACMETTL        uint32
	ACMETokens     map[string]string // bearer-token → canonical _acme-challenge FQDN
	ConfigDir      string
}

type KeepaliveRuntimeConfig struct {
	Interval time.Duration
	Window   time.Duration
	Timeout  time.Duration
}

func (k KeepaliveRuntimeConfig) validate(path string) error {
	if k.Interval <= 0 {
		return fmt.Errorf("%s.interval_seconds must be > 0", path)
	}
	if k.Window <= 0 {
		return fmt.Errorf("%s.window_seconds must be > 0", path)
	}
	if k.Timeout <= 0 {
		return fmt.Errorf("%s.timeout_seconds must be > 0", path)
	}
	return nil
}

func keepaliveFromConfig(c KeepaliveConfig) KeepaliveRuntimeConfig {
	return KeepaliveRuntimeConfig{
		Interval: time.Duration(c.IntervalSeconds) * time.Second,
		Window:   time.Duration(c.WindowSeconds) * time.Second,
		Timeout:  time.Duration(c.TimeoutSeconds) * time.Second,
	}
}

func keepaliveWithOverride(base KeepaliveRuntimeConfig, o KeepaliveOverrideConfig) KeepaliveRuntimeConfig {
	out := base
	if o.IntervalSeconds > 0 {
		out.Interval = time.Duration(o.IntervalSeconds) * time.Second
	}
	if o.WindowSeconds > 0 {
		out.Window = time.Duration(o.WindowSeconds) * time.Second
	}
	if o.TimeoutSeconds > 0 {
		out.Timeout = time.Duration(o.TimeoutSeconds) * time.Second
	}
	return out
}

func keepaliveWithOptionalOverride(base KeepaliveRuntimeConfig, o *KeepaliveOverrideConfig) KeepaliveRuntimeConfig {
	if o == nil {
		return base
	}
	return keepaliveWithOverride(base, *o)
}

func normalizeName(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

func fqdnInZone(name string, zone string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || trimmed == "@" {
		return normalizeName(zone)
	}
	if strings.HasSuffix(trimmed, ".") {
		return normalizeName(trimmed)
	}
	return normalizeName(trimmed + "." + strings.TrimSuffix(zone, "."))
}

func normalizeDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		normalized := normalizeName(domain)
		if normalized == "." {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func matchesAnyDomain(name string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	normalizedName := normalizeName(name)
	for _, domain := range domains {
		if normalizedName == domain || strings.HasSuffix(normalizedName, "."+strings.TrimSuffix(domain, ".")+".") {
			return true
		}
		if strings.HasSuffix(normalizedName, domain) {
			return true
		}
	}
	return false
}

func parseACLPrefixes(values []string, path string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}

	seen := map[string]struct{}{}
	out := make([]netip.Prefix, 0, len(values))
	for i, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		var prefix netip.Prefix
		if strings.Contains(trimmed, "/") {
			parsed, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return nil, fmt.Errorf("%s[%d] must be a valid CIDR prefix or IP address: %w", path, i, err)
			}
			prefix = parsed.Masked()
		} else {
			addr, err := netip.ParseAddr(trimmed)
			if err != nil {
				return nil, fmt.Errorf("%s[%d] must be a valid CIDR prefix or IP address: %w", path, i, err)
			}
			addr = addr.Unmap()
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())

		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, prefix)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out, nil
}

func remoteAddrIP(addr net.Addr) (netip.Addr, error) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			break
		}
		return ip.Unmap(), nil
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			break
		}
		return ip.Unmap(), nil
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(addr.String()))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(addr.String()), "[]")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to parse remote IP %q: %w", addr.String(), err)
	}
	return ip.Unmap(), nil
}

type stringNetAddr struct {
	net string
	str string
}

func (a stringNetAddr) Network() string {
	if strings.TrimSpace(a.net) == "" {
		return "tcp"
	}
	return a.net
}

func (a stringNetAddr) String() string {
	return a.str
}

func addrFromRemoteAddrString(value string) net.Addr {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return stringNetAddr{net: "tcp", str: "0.0.0.0:0"}
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return stringNetAddr{net: "tcp", str: trimmed}
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return stringNetAddr{net: "tcp", str: trimmed}
	}
	p, convErr := strconv.Atoi(port)
	if convErr != nil {
		return &net.TCPAddr{IP: ip, Port: 0}
	}
	return &net.TCPAddr{IP: ip, Port: p}
}

func (acl bindACLRuntime) allowsRemote(addr net.Addr) (bool, error) {
	ip, err := remoteAddrIP(addr)
	if err != nil {
		return false, err
	}

	for _, prefix := range acl.deny {
		if prefix.Contains(ip) {
			return false, nil
		}
	}

	if len(acl.allow) == 0 {
		return true, nil
	}
	for _, prefix := range acl.allow {
		if prefix.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

func parseBindACL(cfg *BindAccessConfig, path string) (bindACLRuntime, error) {
	if cfg == nil {
		return bindACLRuntime{}, fmt.Errorf("%s block is required", path)
	}
	if cfg.Allow == nil {
		return bindACLRuntime{}, fmt.Errorf("%s.allow must be specified", path)
	}
	if cfg.Deny == nil {
		return bindACLRuntime{}, fmt.Errorf("%s.deny must be specified", path)
	}
	allow, err := parseACLPrefixes(cfg.Allow, path+".allow")
	if err != nil {
		return bindACLRuntime{}, err
	}
	deny, err := parseACLPrefixes(cfg.Deny, path+".deny")
	if err != nil {
		return bindACLRuntime{}, err
	}
	return bindACLRuntime{allow: allow, deny: deny}, nil
}

func parseRequiredACL(allowValues []string, denyValues []string, path string) (bindACLRuntime, error) {
	if allowValues == nil {
		return bindACLRuntime{}, fmt.Errorf("%s.allow must be specified", path)
	}
	if denyValues == nil {
		return bindACLRuntime{}, fmt.Errorf("%s.deny must be specified", path)
	}
	allow, err := parseACLPrefixes(allowValues, path+".allow")
	if err != nil {
		return bindACLRuntime{}, err
	}
	deny, err := parseACLPrefixes(denyValues, path+".deny")
	if err != nil {
		return bindACLRuntime{}, err
	}
	return bindACLRuntime{allow: allow, deny: deny}, nil
}

var knownTargets = map[string]string{}

func resolveTarget(name string, zone string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("empty target")
	}
	if known, ok := knownTargets[strings.ToLower(trimmed)]; ok {
		return normalizeName(known), nil
	}
	return fqdnInZone(trimmed, zone), nil
}

func resolveListenAddrs(dnsCfg DNSConfig) ([]ListenBind, error) {
	seen := map[string]struct{}{}
	binds := make([]ListenBind, 0, len(dnsCfg.Binds)*2)

	appendBind := func(addr string, network string, policy bindPolicyRuntime) {
		trimmed := strings.TrimSpace(addr)
		if trimmed == "" {
			return
		}
		netKey := strings.TrimSpace(network)
		key := netKey + "|" + trimmed
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		binds = append(binds, ListenBind{Addr: trimmed, Net: netKey, Policy: policy})
	}

	for _, bind := range dnsCfg.Binds {
		if strings.TrimSpace(bind.Addr) == "" {
			return nil, fmt.Errorf("dns requires addr")
		}
		if bind.Port == 0 {
			return nil, fmt.Errorf("dns requires non-zero port")
		}
		bindPath := fmt.Sprintf("server.dns.bind[%q:%d]", strings.TrimSpace(bind.Addr), bind.Port)
		if bind.Query == nil {
			return nil, fmt.Errorf("%s.query block is required", bindPath)
		}
		if bind.Transfer == nil {
			return nil, fmt.Errorf("%s.transfer block is required", bindPath)
		}
		queryACL, err := parseBindACL(bind.Query, bindPath+".query")
		if err != nil {
			return nil, err
		}
		transferACL, err := parseBindACL(bind.Transfer, bindPath+".transfer")
		if err != nil {
			return nil, err
		}
		trimmedAddr := net.JoinHostPort(strings.TrimSpace(bind.Addr), strconv.Itoa(int(bind.Port)))
		policy := bindPolicyRuntime{query: queryACL, transfer: transferACL}
		appendBind(trimmedAddr, "udp", policy)
		appendBind(trimmedAddr, "tcp", policy)
	}

	if len(binds) == 0 {
		return nil, fmt.Errorf("server.dns requires at least one bind block")
	}

	return binds, nil
}

func isTransferType(qtype uint16) bool {
	return qtype == dns.TypeAXFR || qtype == dns.TypeIXFR
}

func compareRR(a dns.RR, b dns.RR) int {
	ah := a.Header()
	bh := b.Header()
	if ah.Name != bh.Name {
		return strings.Compare(ah.Name, bh.Name)
	}
	if ah.Rrtype != bh.Rrtype {
		if ah.Rrtype < bh.Rrtype {
			return -1
		}
		return 1
	}
	if ah.Class != bh.Class {
		if ah.Class < bh.Class {
			return -1
		}
		return 1
	}
	if ah.Ttl != bh.Ttl {
		if ah.Ttl < bh.Ttl {
			return -1
		}
		return 1
	}
	return strings.Compare(a.String(), b.String())
}

func (cfg *RuntimeConfig) hasZone(name string) bool {
	zone := normalizeName(name)
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	for _, existing := range cfg.Zones {
		if existing == zone {
			return true
		}
	}
	return false
}

func (cfg *RuntimeConfig) zoneTransferEnvelope(zone string, qtype uint16, clientSerial uint32) (*dns.Envelope, error) {
	normZone := normalizeName(zone)
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()

	var soa *dns.SOA
	body := make([]dns.RR, 0)
	for qtypeKey, recordsByName := range cfg.Answers {
		for owner, rrs := range recordsByName {
			if !dns.IsSubDomain(normZone, owner) {
				continue
			}
			for _, rr := range rrs {
				copied := dns.Copy(rr)
				if qtypeKey == dns.TypeSOA && owner == normZone {
					if existing, ok := copied.(*dns.SOA); ok && soa == nil {
						soa = existing
						continue
					}
				}
				body = append(body, copied)
			}
		}
	}
	for owner, values := range cfg.ACMETXT {
		if !dns.IsSubDomain(normZone, owner) {
			continue
		}
		for value := range values {
			body = append(body, &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: cfg.ACMETTL}, Txt: []string{value}})
		}
	}
	if soa == nil {
		return nil, fmt.Errorf("zone %s has no SOA record for transfer", normZone)
	}

	sort.Slice(body, func(i, j int) bool {
		return compareRR(body[i], body[j]) < 0
	})

	if qtype == dns.TypeIXFR && clientSerial == soa.Serial {
		return &dns.Envelope{RR: []dns.RR{dns.Copy(soa)}}, nil
	}

	rrs := make([]dns.RR, 0, len(body)+2)
	rrs = append(rrs, dns.Copy(soa))
	rrs = append(rrs, body...)
	rrs = append(rrs, dns.Copy(soa))
	return &dns.Envelope{RR: rrs}, nil
}

func ixfrClientSerial(msg *dns.Msg, zone string) uint32 {
	normZone := normalizeName(zone)
	for _, rr := range msg.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		if normalizeName(soa.Hdr.Name) != normZone {
			continue
		}
		return soa.Serial
	}
	return 0
}

func writeDNSReply(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err != nil {
		logger.Error().Err(err).Msg("dns response write failed")
	}
	observeDNSResponse(m.Rcode)
}

func handleZoneTransfer(cfg *RuntimeConfig, bind ListenBind, w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) != 1 || !isTransferType(r.Question[0].Qtype) {
		return false
	}

	q := r.Question[0]
	observeDNSQuestion(q.Qtype)
	zoneName := normalizeName(q.Name)

	allowed, err := bind.Policy.transfer.allowsRemote(w.RemoteAddr())
	if err != nil {
		logger.Error().Err(err).Str("remote", w.RemoteAddr().String()).Str("bind_addr", bind.Addr).Str("bind_net", bind.Net).Msg("dns transfer acl evaluation failed")
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		writeDNSReply(w, m)
		return true
	}
	if !allowed {
		logger.Warn().Str("remote", w.RemoteAddr().String()).Str("bind_addr", bind.Addr).Str("bind_net", bind.Net).Str("zone", zoneName).Msg("dns transfer refused by bind acl")
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		writeDNSReply(w, m)
		return true
	}
	if bind.Net != "tcp" {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		writeDNSReply(w, m)
		return true
	}
	if !cfg.hasZone(zoneName) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		writeDNSReply(w, m)
		return true
	}

	envelope, err := cfg.zoneTransferEnvelope(zoneName, q.Qtype, ixfrClientSerial(r, zoneName))
	if err != nil {
		logger.Error().Err(err).Str("zone", zoneName).Str("type", dns.TypeToString[q.Qtype]).Msg("dns zone transfer failed")
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		writeDNSReply(w, m)
		return true
	}

	logger.Info().Str("remote", w.RemoteAddr().String()).Str("bind_addr", bind.Addr).Str("bind_net", bind.Net).Str("zone", zoneName).Str("type", dns.TypeToString[q.Qtype]).Msg("dns zone transfer")
	ch := make(chan *dns.Envelope, 1)
	ch <- envelope
	close(ch)
	if err := (&dns.Transfer{}).Out(w, r, ch); err != nil {
		logger.Error().Err(err).Str("zone", zoneName).Str("type", dns.TypeToString[q.Qtype]).Msg("dns zone transfer write failed")
		observeDNSResponse(dns.RcodeServerFailure)
		return true
	}
	observeDNSResponse(dns.RcodeSuccess)
	return true
}

func loadConfig(configDir string) (*RuntimeConfig, error) {
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read config directory %s: %w", configDir, err)
	}

	var varFilePaths []string // *.vars.hcl — override files
	var cfgFilePaths []string // other *.hcl — definition files
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		lower := strings.ToLower(entry.Name())
		if strings.HasSuffix(lower, ".vars.hcl") {
			varFilePaths = append(varFilePaths, filepath.Join(configDir, entry.Name()))
		} else if filepath.Ext(lower) == ".hcl" {
			cfgFilePaths = append(cfgFilePaths, filepath.Join(configDir, entry.Name()))
		}
	}
	sort.Strings(varFilePaths)
	sort.Strings(cfgFilePaths)
	if len(cfgFilePaths) == 0 {
		return nil, fmt.Errorf("no .hcl config files found in %s", configDir)
	}

	parser := hclparse.NewParser()

	// Parse all config files up-front
	parsedFiles := make([]*hcl.File, len(cfgFilePaths))
	for i, path := range cfgFilePaths {
		file, diags := parser.ParseHCLFile(path)
		if diags.HasErrors() {
			return nil, fmt.Errorf("failed to parse %s: %s", path, diags.Error())
		}
		parsedFiles[i] = file
	}

	// First pass: extract variable blocks (definition + default)
	type varDef struct {
		description string
		hasValue    bool
		value       cty.Value
	}
	varDefs := map[string]varDef{}
	variableSchema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "variable", LabelNames: []string{"name"}}},
	}
	remainingBodies := make([]hcl.Body, len(parsedFiles))
	for i, file := range parsedFiles {
		content, remain, diags := file.Body.PartialContent(variableSchema)
		if diags.HasErrors() {
			return nil, fmt.Errorf("failed to extract variables from %s: %s", cfgFilePaths[i], diags.Error())
		}
		remainingBodies[i] = remain
		for _, block := range content.Blocks {
			name := block.Labels[0]
			attrs, diags := block.Body.JustAttributes()
			if diags.HasErrors() {
				return nil, fmt.Errorf("invalid variable %q in %s: %s", name, cfgFilePaths[i], diags.Error())
			}
			def := varDef{}
			if attr, ok := attrs["description"]; ok {
				if val, diags := attr.Expr.Value(nil); !diags.HasErrors() && val.Type() == cty.String {
					def.description = val.AsString()
				}
			}
			if attr, ok := attrs["default"]; ok {
				if val, diags := attr.Expr.Value(nil); !diags.HasErrors() {
					def.value = val
					def.hasValue = true
				}
			}
			varDefs[name] = def
		}
	}

	// Second pass: apply overrides from *.vars.hcl files
	for _, path := range varFilePaths {
		file, diags := parser.ParseHCLFile(path)
		if diags.HasErrors() {
			return nil, fmt.Errorf("failed to parse %s: %s", path, diags.Error())
		}
		attrs, diags := file.Body.JustAttributes()
		if diags.HasErrors() {
			return nil, fmt.Errorf("invalid overrides in %s: %s", path, diags.Error())
		}
		for name, attr := range attrs {
			val, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("invalid value for variable %q in %s: %s", name, path, diags.Error())
			}
			def := varDefs[name]
			def.value = val
			def.hasValue = true
			varDefs[name] = def
		}
	}

	// Build vars cty object from resolved definitions
	varsMap := map[string]cty.Value{}
	for name, def := range varDefs {
		if def.hasValue {
			varsMap[name] = def.value
		}
	}

	// Environment variable overrides via Viper (prefix DNSD_)
	// e.g. DNSD_PORT_HTTPS=8443 overrides vars.port_https
	v := viper.New()
	v.SetEnvPrefix("DNSD")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	for name := range varDefs {
		v.BindEnv(name)
		if v.IsSet(name) {
			existing, hasExisting := varsMap[name]
			switch {
			case hasExisting && existing.Type() == cty.Number:
				varsMap[name] = cty.NumberUIntVal(uint64(v.GetUint64(name)))
			case hasExisting && existing.Type() == cty.String:
				varsMap[name] = cty.StringVal(v.GetString(name))
			default:
				// No default to infer type from: try number first, then string
				if n := v.GetUint64(name); n != 0 {
					varsMap[name] = cty.NumberUIntVal(n)
				} else {
					varsMap[name] = cty.StringVal(v.GetString(name))
				}
			}
		}
	}
	var evalCtx *hcl.EvalContext
	if len(varsMap) > 0 {
		evalCtx = &hcl.EvalContext{
			Variables: map[string]cty.Value{
				"vars": cty.ObjectVal(varsMap),
			},
		}
	}

	// Third pass: decode server/record/zone blocks with eval context
	merged := Config{}
	serverCount := 0
	for i, body := range remainingBodies {
		var partial PartialConfig
		diags := gohcl.DecodeBody(body, evalCtx, &partial)
		if diags.HasErrors() {
			return nil, fmt.Errorf("failed to decode %s: %s", cfgFilePaths[i], diags.Error())
		}
		serverCount += len(partial.Servers)
		if len(partial.Servers) > 0 {
			merged.Server = partial.Servers[len(partial.Servers)-1]
		}
		merged.Records = append(merged.Records, partial.Records...)
		merged.Zones = append(merged.Zones, partial.Zones...)
	}

	dynamicPartials, err := loadDynamicConfigs(configDir)
	if err != nil {
		return nil, err
	}
	for _, partial := range dynamicPartials {
		if len(partial.Servers) > 0 {
			return nil, fmt.Errorf("dynamic config files in dyndns must not contain server blocks")
		}
		merged.Records = append(merged.Records, partial.Records...)
		merged.Zones = append(merged.Zones, partial.Zones...)
	}

	if serverCount == 0 {
		return nil, fmt.Errorf("no server block found in .hcl files")
	}
	if serverCount > 1 {
		return nil, fmt.Errorf("multiple server blocks found (%d), expected exactly one", serverCount)
	}

	cfg := merged

	if len(cfg.Zones) == 0 {
		return nil, fmt.Errorf("no zone blocks defined")
	}
	if len(cfg.Records) == 0 {
		return nil, fmt.Errorf("no record blocks defined")
	}

	recordsByID := make(map[string]RecordConfig, len(cfg.Records))
	for _, rec := range cfg.Records {
		if rec.ID == "" {
			return nil, fmt.Errorf("record id cannot be empty")
		}
		if _, exists := recordsByID[rec.ID]; exists {
			return nil, fmt.Errorf("duplicate record id: %s", rec.ID)
		}
		recordsByID[rec.ID] = rec
	}

	// Build resolved upstream groups sorted by weight (ascending = highest priority)
	sortedGroups := make([]DNSUpstreamGroupConfig, len(cfg.Server.DNS.Upstream.Groups))
	copy(sortedGroups, cfg.Server.DNS.Upstream.Groups)
	sort.Slice(sortedGroups, func(i, j int) bool {
		return sortedGroups[i].Weight < sortedGroups[j].Weight
	})
	resolvedGroups := make([]resolvedUpstreamGroup, 0, len(sortedGroups))
	serverKeepalive := keepaliveFromConfig(cfg.Server.DNS.Upstream.Keepalive)
	if err := serverKeepalive.validate("server.dns.upstream.keepalive"); err != nil {
		return nil, err
	}

	keepaliveByAddr := map[string]KeepaliveRuntimeConfig{}
	for _, g := range sortedGroups {
		if len(g.Endpoints) == 0 {
			continue
		}
		groupKeepalive := keepaliveWithOptionalOverride(serverKeepalive, g.Keepalive)
		groupPath := fmt.Sprintf("server.dns.upstream.group[%q].keepalive", g.Name)
		if err := groupKeepalive.validate(groupPath); err != nil {
			return nil, err
		}
		entries := make([]upstreamEntry, 0, len(g.Endpoints))
		percents := make([]uint16, 0, len(g.Endpoints))
		var total uint16
		for i, u := range g.Endpoints {
			addr := strings.TrimSpace(u.Addr)
			if u.SystemResolver && addr != "" {
				return nil, fmt.Errorf("server.dns.upstream.group[%q].endpoint[%d] cannot set both addr and system_resolver", g.Name, i)
			}

			targets := make([]string, 0, 1)
			if u.SystemResolver {
				resolverTargets, err := resolveSystemResolverAddrs(u.Port)
				if err != nil {
					return nil, err
				}
				targets = append(targets, resolverTargets...)
			} else {
				if addr == "" {
					continue
				}
				port := u.Port
				if port == 0 {
					port = 53
				}
				targets = append(targets, net.JoinHostPort(addr, strconv.Itoa(int(port))))
			}
			if len(targets) == 0 {
				continue
			}
			splitPercents := splitPercent(u.Percent, len(targets))

			upstreamKeepalive := keepaliveWithOptionalOverride(groupKeepalive, u.Keepalive)
			upstreamPath := fmt.Sprintf("server.dns.upstream.group[%q].endpoint[%d].keepalive", g.Name, i)
			if err := upstreamKeepalive.validate(upstreamPath); err != nil {
				return nil, err
			}

			for idx, fullAddr := range targets {
				if existing, exists := keepaliveByAddr[fullAddr]; exists {
					if existing != upstreamKeepalive {
						return nil, fmt.Errorf("endpoint %s has conflicting keepalive settings across groups/endpoints", fullAddr)
					}
				} else {
					keepaliveByAddr[fullAddr] = upstreamKeepalive
				}

				desc := strings.TrimSpace(u.Description)
				if u.SystemResolver {
					if desc == "" {
						desc = "system resolver"
					}
				}

				entries = append(entries, upstreamEntry{
					addr:        fullAddr,
					description: desc,
					keepalive:   upstreamKeepalive,
				})
				percents = append(percents, splitPercents[idx])
				total += splitPercents[idx]
			}
		}
		if len(entries) == 0 {
			continue
		}
		// If no percents defined, distribute evenly
		if total == 0 {
			even := uint16(100 / len(entries))
			for i := range percents {
				percents[i] = even
			}
			total = even * uint16(len(entries))
		}
		resolvedGroups = append(resolvedGroups, resolvedUpstreamGroup{
			name:     g.Name,
			domains:  normalizeDomains(g.Domains),
			entries:  entries,
			percents: percents,
			total:    total,
		})
	}

	acmeTokens, err := loadACMETokens(configDir)
	if err != nil {
		return nil, err
	}

	runtime := &RuntimeConfig{
		Server:         cfg.Server,
		UpstreamGroups: resolvedGroups,
		UpstreamHealth: map[string]*upstreamHealth{},
		ConfigDir:      configDir,
		Answers:        map[uint16]map[string][]dns.RR{},
		ACMETXT:        map[string]map[string]struct{}{},
		ACMETTL:        resolveACMETTL(cfg.Server.ACME),
		ACMETokens:     acmeTokens,
	}
	if len(resolvedGroups) == 0 {
		return nil, fmt.Errorf("server.dns.upstream requires at least one group with at least one endpoint")
	}

	for _, group := range resolvedGroups {
		for _, entry := range group.entries {
			if _, exists := runtime.UpstreamHealth[entry.addr]; !exists {
				runtime.UpstreamHealth[entry.addr] = &upstreamHealth{}
			}
		}
	}

	for _, zone := range cfg.Zones {
		zoneName := normalizeName(zone.Name)
		runtime.Zones = append(runtime.Zones, zoneName)

		for _, ref := range zone.Records {
			rec, ok := recordsByID[ref]
			if !ok {
				return nil, fmt.Errorf("zone %s references unknown record id: %s", zone.Name, ref)
			}

			if err := addRecordAnswers(runtime, rec, zoneName); err != nil {
				return nil, err
			}
		}
	}

	return runtime, nil
}

// weightedOrder returns entry indices in weighted-random order (sampling without replacement).
func weightedOrder(percents []uint16, total uint16) []int {
	n := len(percents)
	result := make([]int, 0, n)
	rem := make([]int, n)
	for i := range rem {
		rem[i] = i
	}
	remP := make([]uint16, n)
	copy(remP, percents)
	remTotal := total
	for len(rem) > 0 {
		if remTotal == 0 {
			result = append(result, rem...)
			break
		}
		r := uint16(rand.Intn(int(remTotal)))
		var cum uint16
		picked := 0
		for i, p := range remP {
			cum += p
			if r < cum {
				picked = i
				break
			}
		}
		result = append(result, rem[picked])
		remTotal -= remP[picked]
		rem = append(rem[:picked], rem[picked+1:]...)
		remP = append(remP[:picked], remP[picked+1:]...)
	}
	return result
}

func (cfg *RuntimeConfig) isUpstreamAvailable(addr string) bool {
	state, ok := cfg.UpstreamHealth[addr]
	if !ok {
		return true
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.down {
		return true
	}
	return time.Now().After(state.downUntil)
}

func (cfg *RuntimeConfig) markUpstreamDown(entry upstreamEntry, groupName string, window time.Duration, reason error, source string) {
	state, ok := cfg.UpstreamHealth[entry.addr]
	if !ok {
		return
	}
	now := time.Now()
	until := now.Add(window)

	state.mu.Lock()
	wasDown := state.down && now.Before(state.downUntil)
	state.down = true
	state.downUntil = until
	state.mu.Unlock()

	evt := logger.Warn().
		Str("source", source).
		Str("group", groupName).
		Str("upstream", entry.addr).
		Dur("down_window", window)
	if entry.description != "" {
		evt = evt.Str("description", entry.description)
	}
	if reason != nil {
		evt = evt.Err(reason)
	}
	if wasDown {
		evt.Msg("upstream still unhealthy; extending penalty window")
		return
	}
	evt.Msg("upstream marked unhealthy")
}

func (cfg *RuntimeConfig) markUpstreamUp(entry upstreamEntry, groupName string, source string) {
	state, ok := cfg.UpstreamHealth[entry.addr]
	if !ok {
		return
	}
	now := time.Now()

	state.mu.Lock()
	wasDown := state.down && now.Before(state.downUntil)
	state.down = false
	state.downUntil = time.Time{}
	state.mu.Unlock()

	if wasDown {
		evt := logger.Info().
			Str("source", source).
			Str("group", groupName).
			Str("upstream", entry.addr)
		if entry.description != "" {
			evt = evt.Str("description", entry.description)
		}
		evt.Msg("upstream recovered")
	}
}

func checkUpstream(entry upstreamEntry, timeout time.Duration) error {
	client := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	msg.RecursionDesired = true
	resp, _, err := client.Exchange(msg, entry.addr)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("nil DNS response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	return nil
}

func startUpstreamKeepalive(cfg *RuntimeConfig) {
	if len(cfg.UpstreamGroups) == 0 {
		return
	}
	logger.Info().Msg("starting upstream keepalive workers")

	seen := map[string]struct{}{}
	for _, group := range cfg.UpstreamGroups {
		for _, entry := range group.entries {
			if _, done := seen[entry.addr]; done {
				continue
			}
			seen[entry.addr] = struct{}{}

			logger.Info().
				Str("group", group.name).
				Str("upstream", entry.addr).
				Dur("interval", entry.keepalive.Interval).
				Dur("window", entry.keepalive.Window).
				Dur("timeout", entry.keepalive.Timeout).
				Msg("starting upstream keepalive worker")

			go func(groupName string, upstream upstreamEntry) {
				ticker := time.NewTicker(upstream.keepalive.Interval)
				defer ticker.Stop()

				probe := func() {
					if err := checkUpstream(upstream, upstream.keepalive.Timeout); err != nil {
						cfg.markUpstreamDown(upstream, groupName, upstream.keepalive.Window, err, "keepalive")
						return
					}
					cfg.markUpstreamUp(upstream, groupName, "keepalive")
				}

				probe()
				for range ticker.C {
					probe()
				}
			}(group.name, entry)
		}
	}
}

// lookupAdditional resolves A records for an SRV target.
// It checks local answers first, then tries upstream groups in weight order.
// Within each group, upstreams are selected via weighted random; on failure the next is tried.
func lookupAdditional(target string, cfg *RuntimeConfig) []dns.RR {
	norm := normalizeName(target)
	cfg.mu.RLock()
	if rrs, ok := cfg.Answers[dns.TypeA][norm]; ok {
		copied := make([]dns.RR, len(rrs))
		copy(copied, rrs)
		cfg.mu.RUnlock()
		return copied
	}
	cfg.mu.RUnlock()

	if !cfg.hasUpstreamGroups() {
		return nil
	}

	groups := cfg.getUpstreamGroupsSnapshot(norm)
	if len(groups) == 0 {
		return nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(norm, dns.TypeA)
	msg.RecursionDesired = true
	for _, group := range groups {
		for _, idx := range weightedOrder(group.percents, group.total) {
			entry := group.entries[idx]
			if !cfg.isUpstreamAvailable(entry.addr) {
				continue
			}
			c := &dns.Client{Timeout: entry.keepalive.Timeout}
			r, _, err := c.Exchange(msg, entry.addr)
			if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
				cfg.markUpstreamDown(entry, group.name, entry.keepalive.Window, err, "dns-query")
				continue
			}
			cfg.markUpstreamUp(entry, group.name, "dns-query")
			return r.Answer
		}
	}
	return nil
}

func (cfg *RuntimeConfig) hasUpstreamGroups() bool {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return len(cfg.UpstreamGroups) > 0
}

func (cfg *RuntimeConfig) getUpstreamGroupsSnapshot(name string) []resolvedUpstreamGroup {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	groups := make([]resolvedUpstreamGroup, 0, len(cfg.UpstreamGroups))
	for _, group := range cfg.UpstreamGroups {
		if !matchesAnyDomain(name, group.domains) {
			continue
		}
		groups = append(groups, group)
	}
	return groups
}

func handleQueries(cfg *RuntimeConfig, bind ListenBind) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if handleZoneTransfer(cfg, bind, w, r) {
			return
		}

		m := new(dns.Msg)
		m.SetReply(r)

		allowed, err := bind.Policy.query.allowsRemote(w.RemoteAddr())
		if err != nil {
			logger.Error().
				Err(err).
				Str("bind_addr", bind.Addr).
				Str("bind_net", bind.Net).
				Str("remote", w.RemoteAddr().String()).
				Msg("dns acl evaluation failed")
			m.Rcode = dns.RcodeRefused
			if writeErr := w.WriteMsg(m); writeErr != nil {
				logger.Error().Err(writeErr).Msg("dns response write failed")
			}
			observeDNSResponse(m.Rcode)
			return
		}
		if !allowed {
			logger.Warn().
				Str("bind_addr", bind.Addr).
				Str("bind_net", bind.Net).
				Str("remote", w.RemoteAddr().String()).
				Msg("dns query refused by bind query acl")
			m.Rcode = dns.RcodeRefused
			writeDNSReply(w, m)
			return
		}

		logger.Info().
			Str("remote", w.RemoteAddr().String()).
			Int("questions", len(r.Question)).
			Msg("dns query")
		for _, q := range r.Question {
			observeDNSQuestion(q.Qtype)
			questionName := normalizeName(q.Name)
			logger.Info().
				Str("name", q.Name).
				Str("class", dns.ClassToString[q.Qclass]).
				Str("type", dns.TypeToString[q.Qtype]).
				Msg("dns question")
			cfg.mu.RLock()
			recordsByName, ok := cfg.Answers[q.Qtype]
			var answers []dns.RR
			if ok {
				if existing, exists := recordsByName[questionName]; exists {
					answers = make([]dns.RR, len(existing))
					copy(answers, existing)
				}
			}
			if q.Qtype == dns.TypeTXT {
				if acmeValues, exists := cfg.ACMETXT[questionName]; exists {
					for value := range acmeValues {
						answers = append(answers, &dns.TXT{Hdr: dns.RR_Header{Name: questionName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: cfg.ACMETTL}, Txt: []string{value}})
					}
				}
			}
			cfg.mu.RUnlock()
			if len(answers) > 0 {
				for _, rr := range answers {
					m.Answer = append(m.Answer, dns.Copy(rr))
					logger.Info().Str("rr", rr.String()).Msg("dns answer")
				}
				// Populate Additional section for SRV targets
				if q.Qtype == dns.TypeSRV {
					seen := map[string]struct{}{}
					for _, rr := range answers {
						srv, ok := rr.(*dns.SRV)
						if !ok {
							continue
						}
						if _, already := seen[srv.Target]; already {
							continue
						}
						seen[srv.Target] = struct{}{}
						for _, ar := range lookupAdditional(srv.Target, cfg) {
							m.Extra = append(m.Extra, dns.Copy(ar))
							logger.Info().Str("rr", ar.String()).Msg("dns additional")
						}
					}
				}
			}
		}
		writeDNSReply(w, m)
		logger.Info().
			Int("answer_count", len(m.Answer)).
			Int("additional_count", len(m.Extra)).
			Int("rcode", m.Rcode).
			Msg("dns response")
	}
}

func Run(configDir string) error {
	cfg, err := loadConfig(configDir)
	if err != nil {
		return fmt.Errorf("failed to load .hcl config files: %w", err)
	}

	listenAddrs, err := resolveListenAddrs(cfg.Server.DNS)
	if err != nil {
		return fmt.Errorf("invalid server listen configuration: %w", err)
	}

	startUpstreamKeepalive(cfg)

	errCh := make(chan error, len(listenAddrs)+4)
	for _, bind := range listenAddrs {
		mux := dns.NewServeMux()
		handler := handleQueries(cfg, bind)
		for _, zone := range cfg.Zones {
			mux.HandleFunc(zone, handler)
		}
		server := &dns.Server{
			Addr:    bind.Addr,
			Net:     bind.Net,
			Handler: mux,
		}
		logger.Info().
			Str("addr", bind.Addr).
			Str("net", bind.Net).
			Strs("zones", cfg.Zones).
			Msg("starting dns server")
		go func(s *dns.Server) {
			errCh <- s.ListenAndServe()
		}(server)
	}

	if cfg.Server.GRPC != nil {
		if err := startDynamicGRPCServer(cfg, configDir, errCh); err != nil {
			return err
		}
	}

	if cfg.Server.ACME != nil {
		if err := startACMEServer(cfg, cfg.Server.ACME, errCh); err != nil {
			return err
		}
	}

	if cfg.Server.Metrics != nil {
		if err := startMetricsServer(cfg.Server.Metrics, errCh); err != nil {
			return err
		}
	}

	if err := startHealthServer(cfg, &cfg.Server.Health, errCh); err != nil {
		return err
	}

	if err := <-errCh; err != nil {
		return fmt.Errorf("failed to start or run DNS server: %w", err)
	}

	return nil
}

func Validate(configDir string) error {
	cfg, err := loadConfig(configDir)
	if err != nil {
		return fmt.Errorf("failed to load .hcl config files: %w", err)
	}

	if _, err := resolveListenAddrs(cfg.Server.DNS); err != nil {
		return fmt.Errorf("invalid server listen configuration: %w", err)
	}
	if _, err := parseRequiredACL(cfg.Server.Health.Allow, cfg.Server.Health.Deny, "server.health"); err != nil {
		return fmt.Errorf("invalid server health acl configuration: %w", err)
	}
	if _, _, _, _, err := resolveHealthListen(&cfg.Server.Health); err != nil {
		return fmt.Errorf("invalid server health configuration: %w", err)
	}
	if cfg.Server.ACME != nil {
		if _, err := parseRequiredACL(cfg.Server.ACME.Allow, cfg.Server.ACME.Deny, "server.acme"); err != nil {
			return fmt.Errorf("invalid server acme acl configuration: %w", err)
		}
		if _, _, err := resolveACMEListen(cfg.Server.ACME); err != nil {
			return fmt.Errorf("invalid server acme configuration: %w", err)
		}
	}
	if cfg.Server.GRPC != nil {
		if _, err := parseRequiredACL(cfg.Server.GRPC.Allow, cfg.Server.GRPC.Deny, "server.grpc"); err != nil {
			return fmt.Errorf("invalid server grpc acl configuration: %w", err)
		}
	}
	if cfg.Server.Metrics != nil {
		if _, err := parseRequiredACL(cfg.Server.Metrics.Allow, cfg.Server.Metrics.Deny, "server.metrics"); err != nil {
			return fmt.Errorf("invalid server metrics acl configuration: %w", err)
		}
		if _, _, _, err := resolveMetricsListen(cfg.Server.Metrics); err != nil {
			return fmt.Errorf("invalid server metrics configuration: %w", err)
		}
	}

	return nil
}
