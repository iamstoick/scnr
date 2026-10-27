// Package netscan is the native TCP connect scanner: open ports, banners,
// TLS certificate/version/cipher checks and a single HTTP GET for service labels.
// No raw sockets, no root, no retries.
package netscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

//go:embed rules/*.yaml ports_top1000.txt
var assets embed.FS

// Name of the engine.
const Name = "netscan"

const (
	connectTimeout = 2 * time.Second
	bannerTimeout  = 2 * time.Second
	bannerBytes    = 1024
	httpBodyBytes  = 64 << 10
	expiringSoon   = 14 * 24 * time.Hour
	// udpTimeout bounds one UDP response wait. Silence is the common
	// case and means unknown (not closed): without raw sockets there is
	// no ICMP unreachable to tell open from filtered.
	udpTimeout = 2 * time.Second
)

// topUDPPorts are the highest-value UDP probes: resolvers, time, management
// and amplification-abuse services.
var topUDPPorts = []int{53, 69, 123, 161, 500, 1194, 1434, 1900, 4500, 5353, 11211}

var udpServiceNames = map[int]string{
	53:    "dns",
	69:    "tftp",
	123:   "ntp",
	161:   "snmp",
	500:   "ike",
	1194:  "openvpn",
	1434:  "mssql",
	1900:  "ssdp",
	4500:  "ipsec-nat-t",
	5353:  "mdns",
	11211: "memcached",
}

var adminPorts = map[int]string{23: "telnet", 3389: "rdp", 5900: "vnc", 5901: "vnc", 5902: "vnc", 5985: "winrm", 5986: "winrm", 512: "rexec", 513: "rlogin", 514: "rsh"}

var dbPorts = map[int]string{6379: "redis", 6380: "redis", 27017: "mongodb", 27018: "mongodb", 9200: "elasticsearch", 9300: "elasticsearch",
	11211: "memcached", 3306: "mysql", 5432: "postgresql", 1433: "mssql", 1521: "oracle", 5984: "couchdb", 7474: "neo4j", 7687: "neo4j", 9042: "cassandra"}

var tlsPorts = map[int]bool{443: true, 8443: true, 993: true, 995: true, 465: true, 636: true, 989: true, 990: true, 5061: true, 8883: true, 9443: true, 10443: true, 4443: true, 6443: true, 2376: true}

var httpPorts = map[int]bool{80: true, 8080: true, 8000: true, 8008: true, 8081: true, 8888: true, 3000: true, 5000: true, 8880: true, 9080: true, 8001: true, 8090: true}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.{0,200}?)\s*</title>`)

// Engine implements engine.Engine.
type Engine struct {
	rules   engine.RuleSet
	top1000 []int
	now     func() time.Time
	// roots overrides system roots in tests.
	roots *x509.CertPool
}

// New loads embedded rules and the port list.
func New() (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	ports, err := loadPorts()
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rs, top1000: ports, now: time.Now}, nil
}

func loadPorts() ([]int, error) {
	f, err := assets.Open("ports_top1000.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // embedded asset; close cannot fail usefully
	var out []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := strconv.Atoi(line)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %q in embedded list", line)
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Rules exposes the network rule prose so the nmap adapter can emit the
// same net.* findings (and therefore the same fingerprints) as the native
// scanner instead of duplicating the text.
func (e *Engine) Rules() engine.RuleSet { return e.rules }

// Classify maps a port to the exposure rule it triggers (admin or database
// service) and the service name; ok is false for ordinary ports.
func Classify(port int) (ruleID, service string, ok bool) {
	if name, ok := adminPorts[port]; ok {
		return "net.exposed-admin-port", name, true
	}
	if name, ok := dbPorts[port]; ok {
		return "net.exposed-db-port", name, true
	}
	return "", "", false
}

// Supports hosts, ranges and the host behind a URL.
func (e *Engine) Supports(t domain.Target) bool {
	switch t.Type {
	case domain.TargetHost, domain.TargetCIDR, domain.TargetURL:
		return true
	}
	return false
}

// Ports returns the port list for options: explicit --ports, else profile.
func (e *Engine) Ports(o engine.Options) []int {
	if len(o.Ports) > 0 {
		return o.Ports
	}
	switch o.Profile.Ports {
	case "top100":
		return e.top1000[:100]
	default:
		return e.top1000
	}
}

// UDPPorts returns the UDP probe list: explicit --udp-ports, else the top
// UDP list. An explicit empty (from "off") disables UDP probing.
func (e *Engine) UDPPorts(o engine.Options) []int {
	if o.UDPPorts == nil {
		return topUDPPorts
	}
	return o.UDPPorts
}

// ParseUDPPorts parses --udp-ports: top | off | comma list / ranges.
// Empty means the default top list (nil); "off" means none (empty).
func (e *Engine) ParseUDPPorts(spec string) ([]int, error) {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "":
		return nil, nil
	case "top":
		return topUDPPorts, nil
	case "off":
		return []int{}, nil
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if i := strings.Index(part, "-"); i > 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("bad udp port spec %q", part)
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if out == nil {
		out = []int{}
	}
	return out, nil
}

// ParsePorts parses --ports: top100 | top1000 | all | comma list / ranges.
func (e *Engine) ParsePorts(spec string) ([]int, error) {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "":
		return nil, nil
	case "top100":
		return e.top1000[:100], nil
	case "top1000":
		return e.top1000, nil
	case "all":
		out := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			out = append(out, p)
		}
		return out, nil
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if i := strings.Index(part, "-"); i > 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("bad port spec %q", part)
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (e *Engine) hosts(t domain.Target, o engine.Options) ([]string, error) {
	switch t.Type {
	case domain.TargetCIDR:
		p, err := netip.ParsePrefix(t.Value)
		if err != nil {
			return nil, err
		}
		addrs := safety.Hosts(p)
		max := 0
		if o.Limiter != nil {
			max = o.Limiter.MaxHosts
		}
		if max > 0 && len(addrs) > max {
			addrs = addrs[:max]
		}
		out := make([]string, len(addrs))
		for i, a := range addrs {
			out[i] = a.String()
		}
		return out, nil
	case domain.TargetURL:
		return []string{t.Hostname}, nil
	}
	return []string{t.Value}, nil
}

// Plan implements engine.Engine.
func (e *Engine) Plan(_ context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	hosts, err := e.hosts(t, o)
	if err != nil {
		return engine.Plan{}, err
	}
	ports := e.Ports(o)
	udpPorts := e.UDPPorts(o)
	n := len(hosts) * (len(ports) + len(udpPorts))
	rate := 100
	if o.Limiter != nil {
		rate = o.Limiter.RatePerSec
	}
	summary := fmt.Sprintf("%d host(s) x %d port(s) TCP connect, banners, TLS checks at <= %d conn/s", len(hosts), len(ports), rate)
	if len(udpPorts) > 0 {
		summary += fmt.Sprintf("; %d UDP response probes", len(udpPorts))
	}
	if o.Auth.HasDBCredentials() {
		summary += fmt.Sprintf("; mysql authenticated enumeration as %q", o.Auth.DBUser())
	}
	if o.Intrusive {
		summary += fmt.Sprintf("; mysql CVE-2012-2122 probe on MySQL 5.x greetings (up to %d logins)", mysqlCVEAttempts)
		n += mysqlCVEAttempts
	}
	return engine.Plan{
		Summary:     summary,
		EstRequests: n,
		EstDuration: time.Duration(n/rate+1)*time.Second + time.Duration(len(hosts))*connectTimeout,
		Network:     true,
	}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	if o.Dialer == nil {
		return errors.New("netscan requires a scope-checked dialer")
	}
	hosts, err := e.hosts(t, o)
	if err != nil {
		return err
	}
	ports := e.Ports(o)
	udpPorts := e.UDPPorts(o)
	conc := int64(16)
	if o.Limiter != nil && o.Limiter.PerHostConcurrency > 0 {
		conc = int64(o.Limiter.PerHostConcurrency)
	}
	dialer := o.Dialer.WithTimeout(connectTimeout)
	var emitMu sync.Mutex
	safeEmit := func(f domain.Finding) error {
		emitMu.Lock()
		defer emitMu.Unlock()
		return emit(f)
	}
	probes := 0
	for _, host := range hosts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := e.scanHost(ctx, host, ports, udpPorts, conc, dialer, t, o, safeEmit)
		probes += n
		if err != nil {
			if o.Stats != nil {
				o.Stats(engine.Stats{Probes: probes})
			}
			return err
		}
	}
	if o.Stats != nil {
		o.Stats(engine.Stats{Probes: probes})
	}
	return nil
}

type hostResult struct {
	reached bool
	probes  int
}

func (e *Engine) scanHost(ctx context.Context, host string, ports, udpPorts []int, conc int64, dialer *safety.Dialer, t domain.Target, o engine.Options, emit engine.EmitFunc) (int, error) {
	sem := semaphore.NewWeighted(conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	res := hostResult{}
	var firstErr error
	assetKey := "host:" + host
	for _, port := range ports {
		if err := sem.Acquire(ctx, 1); err != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				if safety.IsRefusal(err) {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
				return
			}
			mu.Lock()
			res.reached = true
			mu.Unlock()
			n, err := e.probe(ctx, conn, dialer, host, port, assetKey, t, o, emit)
			mu.Lock()
			res.probes += n
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	if firstErr != nil {
		return res.probes, firstErr
	}
	for _, port := range udpPorts {
		if err := sem.Acquire(ctx, 1); err != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer sem.Release(1)
			if err := e.probeUDP(ctx, dialer, host, port, assetKey, emit); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	if firstErr != nil {
		return res.probes, firstErr
	}
	if !res.reached && o.Log != nil {
		o.Log.Info("host unreachable on all probed ports", "host", host, "ports", len(ports))
	}
	return res.probes, ctx.Err()
}

// probeUDP sends one datagram per payload and reports the port only when
// something answers. Silence yields nothing: without raw sockets there is
// no ICMP unreachable to tell open from filtered, so a quiet port is
// unknown, never closed.
func (e *Engine) probeUDP(ctx context.Context, dialer *safety.Dialer, host string, port int, assetKey string, emit engine.EmitFunc) error {
	loc := net.JoinHostPort(host, strconv.Itoa(port)) + "/udp"
	for _, payload := range udpPayloads(port) {
		raw, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return refusalOnly(err)
		}
		answered, f := udpExchange(raw, payload, e, assetKey, loc, port)
		raw.Close() //nolint:errcheck // single datagram probe
		if answered {
			return emit(f)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// udpExchange writes one datagram and waits for a reply. It reports one
// finding per port at most: the first answer wins.
func udpExchange(raw net.Conn, payload []byte, e *Engine, assetKey, loc string, port int) (bool, domain.Finding) {
	_ = raw.SetDeadline(time.Now().Add(udpTimeout))
	if _, err := raw.Write(payload); err != nil {
		return false, domain.Finding{}
	}
	buf := make([]byte, bannerBytes)
	n, err := raw.Read(buf)
	if err != nil {
		return false, domain.Finding{} // timeout or ICMP unreachable: unknown
	}
	service := udpServiceNames[port]
	f := e.rules.NewFinding("net.open-udp-port", assetKey, loc, domain.Confirmed)
	if service != "" {
		f.Title = fmt.Sprintf("Open UDP port %d (%s, answered)", port, service)
	} else {
		f.Title = fmt.Sprintf("Open UDP port %d (answered)", port)
	}
	red := safety.NewRedactor()
	detail := fmt.Sprintf("%d-byte UDP response", n)
	if text := sanitizeBanner(buf[:n]); text != "" {
		detail += ": " + text
	}
	f.Evidence = []domain.Evidence{red.TextEvidence("response", loc, detail)}
	return true, f
}

// udpPayloads are the datagrams tried per port: silence first (polite),
// then a valid query for services that only answer valid requests.
func udpPayloads(port int) [][]byte {
	switch port {
	case 53:
		return [][]byte{nil, dnsRootQuery()}
	case 123:
		return [][]byte{nil, ntpClientPacket()}
	default:
		return [][]byte{nil}
	}
}

// dnsRootQuery is a minimal RD query for "." NS: any resolver answers,
// open or not.
func dnsRootQuery() []byte {
	return []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x01,
	}
}

// ntpClientPacket is a mode-3 (client) request: any NTP server replies
// with a mode-4 packet.
func ntpClientPacket() []byte {
	p := make([]byte, 48)
	p[0] = 0x1b
	return p
}

// probe handles one open port: banner, TLS, HTTP label, MySQL audit,
// rules. Every follow-up connection (TLS and MySQL probes) goes through
// the same scope-checked dialer as the initial connect. It returns the
// intrusive probe attempts made on this port.
func (e *Engine) probe(ctx context.Context, conn net.Conn, dialer *safety.Dialer, host string, port int, assetKey string, t domain.Target, o engine.Options, emit engine.EmitFunc) (probes int, err error) {
	raw := readBannerRaw(conn)
	banner := sanitizeBanner(raw)
	conn.Close() //nolint:errcheck // probe socket; banner already captured
	loc := net.JoinHostPort(host, strconv.Itoa(port))
	service := guessService(port, banner)
	// A greeting that parses is ground truth: it identifies MySQL on
	// any port, including non-standard ones whose banner carries no
	// "mysql" text for the heuristic above.
	greeting, isMySQL := parseMySQLGreeting(raw)
	if isMySQL {
		service = "mysql"
	}
	red := o.Redactor
	if red == nil {
		red = safety.NewRedactor()
	}

	var evidence []domain.Evidence
	if banner != "" {
		evidence = append(evidence, red.TextEvidence("banner", loc, banner))
	}
	isTLS := tlsPorts[port] || (banner == "" && !httpPorts[port] && looksLikeTLSPort(port))
	if isTLS {
		tlsEv, tlsFindings, err := e.checkTLS(ctx, dialer, host, assetKey, loc)
		if err != nil {
			return probes, err
		}
		evidence = append(evidence, tlsEv...)
		for _, f := range tlsFindings {
			if err := emit(f); err != nil {
				return probes, err
			}
		}
		if len(tlsEv) > 0 && service == "" {
			service = "tls"
		}
	}
	if o.HTTP != nil && (httpPorts[port] || isTLS) {
		scheme := "http"
		if isTLS {
			scheme = "https"
		}
		label, ev, redir := e.httpProbe(ctx, o.HTTP, scheme, loc, red)
		if label != "" {
			service = label
		}
		if ev != nil {
			evidence = append(evidence, *ev)
		}
		if redir != nil {
			f := e.rules.NewFinding("web.redirect-out-of-scope", assetKey, redir.From, domain.Confirmed)
			f.Evidence = []domain.Evidence{red.TextEvidence("response", redir.From, "Location: "+redir.To)}
			if err := emit(f); err != nil {
				return probes, err
			}
		}
	}

	f := e.rules.NewFinding("net.open-port", assetKey, loc, domain.Confirmed)
	if service != "" {
		f.Title = fmt.Sprintf("Open TCP port %d (%s)", port, service)
	} else {
		f.Title = fmt.Sprintf("Open TCP port %d", port)
	}
	f.Evidence = evidence
	if err := emit(f); err != nil {
		return probes, err
	}
	if name, ok := adminPorts[port]; ok {
		f := e.rules.NewFinding("net.exposed-admin-port", assetKey, loc, domain.Firm)
		f.Title = fmt.Sprintf("Remote administration service exposed (%s on %d)", name, port)
		if !t.Public {
			f.Severity = domain.Medium
		}
		f.Evidence = evidence
		if err := emit(f); err != nil {
			return probes, err
		}
	}
	if name, ok := dbPorts[port]; ok {
		f := e.rules.NewFinding("net.exposed-db-port", assetKey, loc, domain.Firm)
		f.Title = fmt.Sprintf("Database or cache service exposed (%s on %d)", name, port)
		if !t.Public {
			f.Severity = domain.Medium
		}
		f.Evidence = evidence
		if err := emit(f); err != nil {
			return probes, err
		}
	}
	if isMySQL {
		n, err := e.auditMySQL(ctx, dialer, host, loc, assetKey, greeting, o, red, emit)
		probes += n
		if err != nil {
			return probes, err
		}
	}
	return probes, nil
}

func looksLikeTLSPort(port int) bool { return port%1000 == 443 }

// readBannerRaw captures the single banner read as raw bytes so binary
// greetings (MySQL) can be parsed as well as displayed.
func readBannerRaw(conn net.Conn) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(bannerTimeout))
	buf := make([]byte, bannerBytes)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	return buf[:n]
}

// sanitizeBanner renders raw banner bytes for display and matching.
func sanitizeBanner(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(safety.StripControl(string(raw)))
}

func guessService(port int, banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(b, "ssh-"):
		return "ssh"
	case strings.HasPrefix(b, "220") && strings.Contains(b, "ftp"):
		return "ftp"
	case strings.HasPrefix(b, "220") && (strings.Contains(b, "smtp") || strings.Contains(b, "esmtp")):
		return "smtp"
	case strings.HasPrefix(b, "+ok"):
		return "pop3"
	case strings.HasPrefix(b, "* ok"):
		return "imap"
	case strings.Contains(b, "mysql") || strings.Contains(b, "mariadb"):
		return "mysql"
	case strings.HasPrefix(b, "-err") || strings.Contains(b, "redis"):
		return "redis"
	}
	if n, ok := adminPorts[port]; ok {
		return n
	}
	if n, ok := dbPorts[port]; ok {
		return n
	}
	if httpPorts[port] {
		return "http"
	}
	return ""
}

// checkTLS performs the default handshake (to capture the chain), legacy
// version probes, and per-cipher acceptance probes for TLS 1.0-1.2.
// InsecureSkipVerify is used only to obtain the peer certificate for
// inspection; trust is then evaluated explicitly with x509.Verify so the
// result can be reported rather than hidden. The TCP connection comes from
// the scope-checked dialer (DNS pinning, deny list, rate limit), never from
// a raw net.Dialer on the hostname. Ordinary connect/handshake failures
// yield no evidence; a safety refusal is returned so the scan stops rather
// than silently skipping the check. TLS 1.3 ciphers are not individually
// probeable with crypto/tls, so 1.3 is reported as the negotiated version
// only.
func (e *Engine) checkTLS(ctx context.Context, dialer *safety.Dialer, host string, assetKey, loc string) ([]domain.Evidence, []domain.Finding, error) {
	serverName := host
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsValid() {
		serverName = "" // SNI not sent for IP literals
	}
	raw, err := dialer.DialContext(ctx, "tcp", loc)
	if err != nil {
		return nil, nil, refusalOnly(err)
	}
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: tls.VersionTLS10} //nolint:gosec // inspection only, see comment
	tc := tls.Client(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(connectTimeout * 2))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close() //nolint:errcheck // first handshake failed; retry offering insecure ciphers for weak-only servers
		raw2, err := dialer.DialContext(ctx, "tcp", loc)
		if err != nil {
			return nil, nil, refusalOnly(err)
		}
		ids := make([]uint16, 0, len(cipherCandidates()))
		for _, suite := range cipherCandidates() {
			ids = append(ids, suite.ID)
		}
		cfg2 := &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: ids} //nolint:gosec // weak-only fallback
		tc2 := tls.Client(raw2, cfg2)
		_ = tc2.SetDeadline(time.Now().Add(connectTimeout * 2))
		if err := tc2.HandshakeContext(ctx); err != nil {
			raw2.Close() //nolint:errcheck // not TLS or no shared cipher; nothing to report
			return nil, nil, nil
		}
		state := tc2.ConnectionState()
		tc2.Close() //nolint:errcheck // state already captured
		if len(state.PeerCertificates) == 0 {
			return nil, nil, nil
		}
		return e.finishTLS(ctx, dialer, host, assetKey, loc, serverName, state)
	}
	state := tc.ConnectionState()
	tc.Close() //nolint:errcheck // state already captured
	return e.finishTLS(ctx, dialer, host, assetKey, loc, serverName, state)
}

// finishTLS evaluates the negotiated connection: certificate findings,
// legacy version probes, and cipher enumeration.
func (e *Engine) finishTLS(ctx context.Context, dialer *safety.Dialer, host, assetKey, loc, serverName string, state tls.ConnectionState) ([]domain.Evidence, []domain.Finding, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, nil, nil
	}
	leaf := state.PeerCertificates[0]
	now := e.now()
	var findings []domain.Finding
	certInfo := fmt.Sprintf("subject=%q issuer=%q notBefore=%s notAfter=%s sans=%v version=%s",
		leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339), leaf.DNSNames, tls.VersionName(state.Version))
	evidence := []domain.Evidence{{Kind: "cert", Location: loc, Redacted: certInfo, Hash: domain.SHA256Hex(string(leaf.Raw))}}

	mk := func(id string) domain.Finding {
		f := e.rules.NewFinding(id, assetKey, loc, domain.Confirmed)
		f.Evidence = evidence
		return f
	}
	if now.After(leaf.NotAfter) {
		findings = append(findings, mk("net.tls.expired"))
	} else if leaf.NotAfter.Sub(now) < expiringSoon {
		findings = append(findings, mk("net.tls.expiring-soon"))
	}
	// Chain trust (without hostname) then hostname separately.
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: e.roots, Intermediates: inter, CurrentTime: now}
	if _, err := leaf.Verify(opts); err != nil {
		var ua x509.UnknownAuthorityError
		var inv x509.CertificateInvalidError
		if errors.As(err, &ua) || (errors.As(err, &inv) && inv.Reason != x509.Expired) || leaf.Issuer.String() == leaf.Subject.String() {
			findings = append(findings, mk("net.tls.self-signed"))
		}
	}
	if err := leaf.VerifyHostname(host); err != nil {
		findings = append(findings, mk("net.tls.hostname-mismatch"))
	}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		offers, err := e.offersVersion(ctx, dialer, loc, serverName, v)
		if err != nil {
			return nil, nil, err
		}
		if offers {
			f := mk("net.tls.legacy-version")
			f.Title = "Legacy TLS version accepted (" + tls.VersionName(v) + ")"
			f.Location = loc + "/" + tls.VersionName(v)
			f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, f.Location)
			findings = append(findings, f)
		}
	}
	accepted, weak, cipherEv, err := e.enumerateCiphers(ctx, dialer, loc, serverName, state.Version, state.CipherSuite)
	if err != nil {
		return nil, nil, err
	}
	if cipherEv != nil {
		evidence = append(evidence, *cipherEv)
		inv := e.rules.NewFinding("net.tls.cipher-inventory", assetKey, loc, domain.Confirmed)
		inv.Title = fmt.Sprintf("TLS cipher suites accepted (%d)", len(accepted))
		inv.Evidence = evidence
		findings = append(findings, inv)
		if len(weak) > 0 {
			wf := e.rules.NewFinding("net.tls.weak-cipher", assetKey, loc, domain.Confirmed)
			wf.Title = fmt.Sprintf("Weak TLS cipher accepted (%s)", strings.Join(weak, ", "))
			wf.Evidence = evidence
			findings = append(findings, wf)
		}
	}
	return evidence, findings, nil
}

func (e *Engine) offersVersion(ctx context.Context, dialer *safety.Dialer, loc, serverName string, v uint16) (bool, error) {
	raw, err := dialer.DialContext(ctx, "tcp", loc)
	if err != nil {
		return false, refusalOnly(err)
	}
	defer raw.Close()                                                                                  //nolint:errcheck // version probe; boolean already decided
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: v, MaxVersion: v} //nolint:gosec // handshake-only version probe
	tc := tls.Client(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(connectTimeout * 2))
	return tc.HandshakeContext(ctx) == nil, nil
}

// cipherCandidates lists every TLS 1.0-1.2 cipher the client can offer,
// deduplicated by ID. TLS 1.3 suites (0x1301-0x1303) are not configurable
// in crypto/tls and are reported from the initial handshake instead.
func cipherCandidates() []*tls.CipherSuite {
	seen := map[uint16]bool{}
	var out []*tls.CipherSuite
	for _, suite := range append(append([]*tls.CipherSuite{}, tls.CipherSuites()...), tls.InsecureCipherSuites()...) {
		if suite.ID == 0x1301 || suite.ID == 0x1302 || suite.ID == 0x1303 {
			continue
		}
		if seen[suite.ID] {
			continue
		}
		seen[suite.ID] = true
		out = append(out, suite)
	}
	return out
}

// insecureCipherIDs marks the cipher IDs Go considers insecure by default.
func insecureCipherIDs() map[uint16]bool {
	m := map[uint16]bool{}
	for _, suite := range tls.InsecureCipherSuites() {
		m[suite.ID] = true
	}
	return m
}

// isWeakCipher reports ciphers with broken or deprecated primitives.
func isWeakCipher(id uint16, name string, insecure map[uint16]bool) bool {
	if insecure[id] {
		return true
	}
	upper := strings.ToUpper(name)
	for _, weak := range []string{"RC4", "DES", "NULL", "EXPORT", "ANON", "_MD5"} {
		if strings.Contains(upper, weak) {
			return true
		}
	}
	return false
}

// offersCipher probes one cipher suite within TLS 1.0-1.2. It returns the
// accepted flag and the negotiated version name.
func (e *Engine) offersCipher(ctx context.Context, dialer *safety.Dialer, loc, serverName string, id uint16) (bool, string, error) {
	raw, err := dialer.DialContext(ctx, "tcp", loc)
	if err != nil {
		return false, "", refusalOnly(err)
	}
	defer raw.Close() //nolint:errcheck // cipher probe; boolean already decided
	cfg := &tls.Config{ //nolint:gosec // handshake-only cipher probe
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{id},
	}
	tc := tls.Client(raw, cfg)
	_ = tc.SetDeadline(time.Now().Add(connectTimeout * 2))
	if err := tc.HandshakeContext(ctx); err != nil {
		return false, "", nil
	}
	return true, tls.VersionName(tc.ConnectionState().Version), nil
}

// enumerateCiphers probes every candidate cipher and returns the accepted
// names, the weak subset, and inventory evidence. The initial handshake's
// cipher is always included so TLS 1.3-only servers still report one suite.
func (e *Engine) enumerateCiphers(ctx context.Context, dialer *safety.Dialer, loc, serverName string, initialVersion uint16, initialCipher uint16) ([]string, []string, *domain.Evidence, error) {
	candidates := cipherCandidates()
	byName := make(map[string]uint16, len(candidates))
	for _, suite := range candidates {
		byName[suite.Name] = suite.ID
	}
	insecure := insecureCipherIDs()
	acceptedByName := map[string]string{}
	for _, suite := range candidates {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		ok, version, err := e.offersCipher(ctx, dialer, loc, serverName, suite.ID)
		if err != nil {
			return nil, nil, nil, err
		}
		if ok {
			acceptedByName[suite.Name] = version
		}
	}
	if name := tls.CipherSuiteName(initialCipher); name != "" {
		if _, ok := acceptedByName[name]; !ok {
			acceptedByName[name] = tls.VersionName(initialVersion)
		}
	}
	if len(acceptedByName) == 0 {
		return nil, nil, nil, nil
	}
	names := make([]string, 0, len(acceptedByName))
	for name := range acceptedByName {
		names = append(names, name)
	}
	sort.Strings(names)
	withVersions := make([]string, 0, len(names))
	var weak []string
	for _, name := range names {
		withVersions = append(withVersions, name+" ("+acceptedByName[name]+")")
		if isWeakCipher(byName[name], name, insecure) {
			weak = append(weak, name)
		}
	}
	sort.Strings(weak)
	summary := "accepted=" + strings.Join(withVersions, ", ")
	ev := &domain.Evidence{Kind: "ciphers", Location: loc, Redacted: summary, Hash: domain.SHA256Hex(strings.Join(names, ","))}
	return names, weak, ev, nil
}

// refusalOnly keeps safety refusals (scope, pin, deny, limiter) and drops
// ordinary network errors, which the scanner treats as "port not probeable".
func refusalOnly(err error) error {
	if safety.IsRefusal(err) {
		return err
	}
	return nil
}

// httpProbe does a single GET / for Server header and title.
func (e *Engine) httpProbe(ctx context.Context, client *http.Client, scheme, loc string, red *safety.Redactor) (label string, ev *domain.Evidence, redir *safety.RedirectOutOfScopeError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+loc+"/", nil)
	if err != nil {
		return "", nil, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		if r, ok := safety.AsRedirectOutOfScope(err); ok {
			return "", nil, r
		}
		return "", nil, nil
	}
	body, _ := safety.ReadBody(resp, httpBodyBytes)
	server := resp.Header.Get("Server")
	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.TrimSpace(string(m[1]))
	}
	parts := []string{scheme}
	if server != "" {
		parts = append(parts, server)
	}
	if title != "" {
		parts = append(parts, fmt.Sprintf("%q", title))
	}
	summary := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if server != "" {
		summary += " Server: " + server
	}
	if title != "" {
		summary += " Title: " + title
	}
	e2 := red.TextEvidence("response", scheme+"://"+loc+"/", summary)
	return strings.Join(parts, " "), &e2, nil
}
