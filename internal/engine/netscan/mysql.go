// MySQL audit: passive greeting parse plus optional authenticated
// enumeration and one bounded vulnerability probe (CVE-2012-2122),
// the defensive subset of nmap's mysql-* scripts.
//
// Three tiers, each strictly opt-in deeper than the last:
//
//  1. Handshake (always): parses the server greeting out of the banner
//     bytes the connect probe already captured. No extra connections,
//     no login attempts.
//  2. Authenticated enumeration (needs --auth-file mysql login):
//     SHOW VARIABLES / SHOW DATABASES / mysql.user reads from a fixed
//     read-only query allowlist, using a login released only for the
//     exact host:port being probed.
//  3. CVE-2012-2122 probe (needs o.Intrusive from the gate): repeated
//     wrong-password logins that can only succeed against the memcmp
//     fail-open bug. Bounded, aborts on transport trouble, and runs
//     only against greeting versions in an affected family. Every
//     attempt goes through the scope-checked dialer and the count is
//     reported via Stats.
//
// What is deliberately NOT here: password guessing (mysql-brute),
// any statement outside the read-only allowlist, and sending
// credentials over a connection the server did not offer to encrypt
// when the auth exchange would need cleartext.
package netscan

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // wire protocol mandates SHA1; not a security choice
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// MySQL capability flags (client subset we negotiate).
const (
	mysqlClientProtocol41 uint32 = 1 << 9
	mysqlClientSecureConn uint32 = 1 << 15
	mysqlClientPluginAuth uint32 = 1 << 19
	mysqlClientSSL        uint32 = 1 << 11
	mysqlNegotiableCaps   uint32 = mysqlClientProtocol41 | mysqlClientSecureConn | mysqlClientPluginAuth
	mysqlAuthNative       string = "mysql_native_password"
	mysqlAuthSHA2         string = "caching_sha2_password"
	mysqlAuthSHA256       string = "sha256_password"
	mysqlAuthOld          string = "mysql_old_password"
	mysqlHandshakeCharset byte   = 33 // utf8_general_ci
	mysqlMaxPacketSize    uint32 = 16777215
	mysqlIOTimeout               = 5 * time.Second
	mysqlMaxPacketBytes          = 16 << 20
	mysqlMaxRows                 = 10000
	// mysqlCVEAttempts bounds the CVE-2012-2122 probe: each wrong-password
	// login succeeds with probability ~1/256 on a vulnerable server, so
	// 300 attempts detect it with probability ~69% while keeping the
	// login burst small. The loop stops at the first success.
	mysqlCVEAttempts = 300
	// mysqlCVEUser must exist on the server for the memcmp path to run;
	// root exists on virtually every MySQL install. The password sent is
	// always random and wrong: success proves the bypass, nothing more.
	mysqlCVEUser       = "root"
	mysqlMaxConsecErr  = 10
	mysqlProbePassword = 12 // random bytes per CVE attempt
)

// Read-only query allowlist for authenticated enumeration. Nothing else
// is ever sent on an authenticated session.
const (
	mysqlQVariables  = "SHOW GLOBAL VARIABLES"
	mysqlQDatabases  = "SHOW DATABASES"
	mysqlQUsers      = "SELECT user, host, authentication_string, plugin FROM mysql.user"
	mysqlQUsersOld   = "SELECT user, host, password, plugin FROM mysql.user"
	mysqlErrNoTable  = 1146
	mysqlErrNoColumn = 1054
)

// mysqlGreeting is the parsed Initial Handshake packet.
type mysqlGreeting struct {
	Version    string
	MariaDB    bool
	Caps       uint32
	AuthPlugin string
	Scramble   []byte // 20-byte auth-plugin-data
}

// TLSCapable reports whether the server offers TLS (CLIENT_SSL).
func (g mysqlGreeting) TLSCapable() bool { return g.Caps&mysqlClientSSL != 0 }

// parseMySQLGreeting parses a server greeting from raw banner bytes:
// the 4-byte packet header plus the HandshakeV10 payload. Anything
// malformed, truncated or not protocol-41 is rejected so a non-MySQL
// banner can never produce findings.
func parseMySQLGreeting(raw []byte) (mysqlGreeting, bool) {
	var g mysqlGreeting
	if len(raw) < 4 || raw[3] != 0 {
		return g, false
	}
	ln := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
	if ln < 32 || len(raw) < 4+ln {
		return g, false
	}
	return parseGreetingPayload(raw[4 : 4+ln])
}

// parseGreetingPayload parses the HandshakeV10 payload (header stripped).
func parseGreetingPayload(p []byte) (mysqlGreeting, bool) {
	var g mysqlGreeting
	if len(p) < 2 || p[0] != 10 {
		return g, false
	}
	rest := p[1:]
	version, rest, ok := cstring(rest)
	if !ok || !looksLikeVersion(version) {
		return g, false
	}
	if len(rest) < 4+8+1+2 {
		return g, false
	}
	rest = rest[4:] // connection id
	scr1 := append([]byte(nil), rest[:8]...)
	rest = rest[8:]
	if rest[0] != 0 {
		return g, false
	}
	rest = rest[1:]
	caps := uint32(rest[0]) | uint32(rest[1])<<8
	rest = rest[2:]
	if caps&(mysqlClientProtocol41|mysqlClientSecureConn) != mysqlClientProtocol41|mysqlClientSecureConn {
		return g, false
	}
	if len(rest) < 1+2+2+1+10 {
		return g, false
	}
	rest = rest[1+2:] // charset, status flags
	caps |= uint32(rest[0])<<16 | uint32(rest[1])<<24
	rest = rest[2:]
	authLen := int(rest[0])
	rest = rest[1+10:] // auth-plugin-data length, reserved
	partLen := authLen - 8
	if partLen < 13 {
		partLen = 13
	}
	if len(rest) < partLen {
		return g, false
	}
	scr := append(scr1, rest[:partLen]...)
	rest = rest[partLen:]
	plugin, _, ok := cstring(rest)
	if !ok {
		return g, false
	}
	if len(scr) < 20 {
		return g, false
	}
	g = mysqlGreeting{
		Version:    version,
		MariaDB:    strings.Contains(strings.ToLower(version), "mariadb"),
		Caps:       caps,
		AuthPlugin: plugin,
		Scramble:   scr[:20],
	}
	return g, true
}

// cstring splits a NUL-terminated string off the front of p.
func cstring(p []byte) (string, []byte, bool) {
	i := 0
	for i < len(p) && p[i] != 0 {
		i++
	}
	if i >= len(p) {
		return "", p, false
	}
	return string(p[:i]), p[i+1:], true
}

// looksLikeVersion requires a leading dotted major.minor so random
// binary can never parse as a server version.
func looksLikeVersion(s string) bool {
	major, rest, ok := strings.Cut(s, ".")
	if !ok {
		return false
	}
	minor, _, _ := strings.Cut(rest, ".")
	if _, err := strconv.Atoi(major); err != nil {
		return false
	}
	// Minor may carry a suffix ("5b"); the leading run must be numeric.
	digits := 0
	for digits < len(minor) && minor[digits] >= '0' && minor[digits] <= '9' {
		digits++
	}
	return digits > 0
}

// mysqlMajorMinor extracts the leading major.minor from a server version
// string ("8.0.36", "5.5.68-MariaDB", "10.11.7-MariaDB-1:10.11.7").
func mysqlMajorMinor(version string) (major, minor int, ok bool) {
	majorS, rest, found := strings.Cut(version, ".")
	if !found {
		return 0, 0, false
	}
	minorS, _, _ := strings.Cut(rest, ".")
	digits := 0
	for digits < len(minorS) && minorS[digits] >= '0' && minorS[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(majorS)
	minor, err2 := strconv.Atoi(minorS[:digits])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// mysqlCVEFamily reports whether the version is in the CVE-2012-2122
// affected range (MySQL/MariaDB 5.0-5.5; the scramble check was fixed
// for 5.6+). Unparseable versions fail closed.
func mysqlCVEFamily(version string) bool {
	major, minor, ok := mysqlMajorMinor(version)
	if !ok {
		return false
	}
	return major == 5 && minor <= 5
}

// mysqlWire frames packets over one connection: 3-byte length plus
// sequence, then the payload. Reads loop to a full packet so TCP
// fragmentation can never truncate a greeting or a row.
type mysqlWire struct {
	conn net.Conn
	seq  uint8
}

func (w *mysqlWire) readPacket() ([]byte, error) {
	if err := w.conn.SetDeadline(time.Now().Add(mysqlIOTimeout)); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := readFull(w.conn, hdr[:]); err != nil {
		return nil, err
	}
	ln := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	w.seq = hdr[3] + 1
	if ln > mysqlMaxPacketBytes {
		return nil, fmt.Errorf("mysql: packet of %d bytes exceeds cap", ln)
	}
	out := make([]byte, ln)
	if _, err := readFull(w.conn, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (w *mysqlWire) writePacket(payload []byte) error {
	if err := w.conn.SetDeadline(time.Now().Add(mysqlIOTimeout)); err != nil {
		return err
	}
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), w.seq}
	w.seq++
	if _, err := w.conn.Write(hdr); err != nil {
		return err
	}
	_, err := w.conn.Write(payload)
	return err
}

func readFull(conn net.Conn, b []byte) (int, error) {
	done := 0
	for done < len(b) {
		n, err := conn.Read(b[done:])
		done += n
		if err != nil {
			return done, err
		}
		if n == 0 {
			return done, fmt.Errorf("mysql: short read")
		}
	}
	return done, nil
}

// mysqlAuthError is a server rejection (wrong password, access denied):
// expected, never a scan failure, never echoed with credentials.
type mysqlAuthError struct {
	Errno int
}

func (e *mysqlAuthError) Error() string {
	return fmt.Sprintf("mysql auth rejected (errno %d)", e.Errno)
}

// mysqlLogin performs the client side of the connection phase on a fresh
// connection: greeting, optional TLS upgrade when the server offers it,
// then the password exchange for the server's auth plugin. Only the
// scramble-first plugins are supported; anything else fails closed
// without sending credentials. The password is never logged.
func mysqlLogin(conn net.Conn, serverName, user, pass string) error {
	wire := &mysqlWire{conn: conn}
	raw, err := wire.readPacket()
	if err != nil {
		return err
	}
	g, ok := parseGreetingPayload(raw)
	if !ok {
		return fmt.Errorf("mysql: no server greeting")
	}
	switch g.AuthPlugin {
	case mysqlAuthNative, mysqlAuthSHA2, mysqlAuthSHA256:
	default:
		return fmt.Errorf("mysql: unsupported auth plugin")
	}
	caps := g.Caps & mysqlNegotiableCaps
	tlsActive := false
	if g.TLSCapable() {
		req := make([]byte, 4+4+1+23)
		putU32(req[0:], caps|mysqlClientSSL)
		putU32(req[4:], mysqlMaxPacketSize)
		req[8] = mysqlHandshakeCharset
		if err := wire.writePacket(req); err != nil {
			return err
		}
		// Unverified encryption: defeats passive sniffing of the
		// login on the audit path. Same posture as the TLS
		// certificate inspection elsewhere in this engine.
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: serverName}) //nolint:gosec // see comment
		if err := tc.Handshake(); err != nil {
			return err
		}
		wire = &mysqlWire{conn: tc, seq: wire.seq}
		tlsActive = true
	}
	resp := mysqlResponse(caps, user, mysqlToken(pass, g.Scramble), g.AuthPlugin)
	if err := wire.writePacket(resp); err != nil {
		return err
	}
	return mysqlAuthLoop(wire, pass, tlsActive)
}

// mysqlAuthLoop reads auth-phase replies until OK, rejection, or an
// exchange we refuse (cleartext without TLS, unknown plugin switch).
func mysqlAuthLoop(wire *mysqlWire, pass string, tlsActive bool) error {
	for {
		p, err := wire.readPacket()
		if err != nil {
			return err
		}
		if len(p) == 0 {
			return fmt.Errorf("mysql: empty auth reply")
		}
		switch p[0] {
		case 0x00:
			if len(p) == 1 {
				// caching_sha2 fast_auth_success: the final OK
				// follows on the wire.
				next, err := wire.readPacket()
				if err != nil {
					return err
				}
				if len(next) == 0 || next[0] == 0x00 {
					return nil
				}
				if next[0] == 0xff {
					return mysqlErrPacket(next)
				}
				return fmt.Errorf("mysql: unexpected packet after fast auth")
			}
			return nil // OK packet ends the exchange
		case 0xff:
			return mysqlErrPacket(p)
		case 0xfe: // AuthSwitchRequest: plugin name + new scramble
			name, rest, ok := cstring(p[1:])
			if !ok {
				return fmt.Errorf("mysql: malformed auth switch")
			}
			switch name {
			case mysqlAuthNative, mysqlAuthSHA2, mysqlAuthSHA256:
			default:
				return fmt.Errorf("mysql: server switched to an unsupported auth plugin")
			}
			scr := rest
			if len(scr) > 20 {
				scr = scr[:20]
			}
			if err := wire.writePacket(mysqlToken(pass, scr)); err != nil {
				return err
			}
		case 0x01: // AuthMoreData: full authentication requested
			if !tlsActive {
				return fmt.Errorf("mysql: server requires cleartext authentication without TLS")
			}
			if err := wire.writePacket(append([]byte(pass), 0)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("mysql: unexpected auth reply")
		}
	}
}

// mysqlErrPacket converts an ERR packet to a typed auth error. The
// server message is dropped: it is untrusted text and must never reach
// logs or findings beside the login attempt.
func mysqlErrPacket(p []byte) error {
	errno := 0
	if len(p) >= 3 {
		errno = int(p[1]) | int(p[2])<<8
	}
	return &mysqlAuthError{Errno: errno}
}

// mysqlResponse builds the HandshakeResponse41 packet. Database name is
// never requested: enumeration uses fully qualified reads only.
func mysqlResponse(caps uint32, user string, token []byte, plugin string) []byte {
	out := make([]byte, 0, 64+len(user)+len(token)+len(plugin))
	var hdr [32]byte
	putU32(hdr[0:], caps&mysqlNegotiableCaps)
	putU32(hdr[4:], mysqlMaxPacketSize)
	hdr[8] = mysqlHandshakeCharset
	out = append(out, hdr[:]...)
	out = append(out, user...)
	out = append(out, 0)
	out = append(out, mysqlLenEncBytes(token)...)
	if caps&mysqlClientPluginAuth != 0 {
		out = append(out, plugin...)
		out = append(out, 0)
	}
	return out
}

func putU32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

// mysqlToken is the mysql_native_password/caching_sha2_password first
// stage: SHA1(pass) XOR SHA1(scramble + SHA1(SHA1(pass))). Empty
// passwords send an empty response.
func mysqlToken(pass string, scramble []byte) []byte {
	if pass == "" {
		return []byte{}
	}
	h1 := sha1.Sum([]byte(pass)) //nolint:gosec // wire protocol, see import
	h2 := sha1.Sum(h1[:])        //nolint:gosec // wire protocol, see import
	mac := sha1.New()            //nolint:gosec // wire protocol, see import
	mac.Write(scramble)
	mac.Write(h2[:])
	stage := mac.Sum(nil)
	out := make([]byte, len(h1))
	for i := range out {
		out[i] = h1[i] ^ stage[i]
	}
	return out
}

// mysqlQuery runs one allowlisted read-only statement and returns the
// text-protocol rows (positional string columns, NULL as "").
func mysqlQuery(wire *mysqlWire, query string) ([][]string, error) {
	switch query {
	case mysqlQVariables, mysqlQDatabases, mysqlQUsers, mysqlQUsersOld:
	default:
		return nil, fmt.Errorf("mysql: query not in allowlist")
	}
	if err := wire.writePacket(append([]byte{0x03}, query...)); err != nil {
		return nil, err
	}
	head, err := wire.readPacket()
	if err != nil {
		return nil, err
	}
	if len(head) == 0 {
		return nil, fmt.Errorf("mysql: empty result")
	}
	switch head[0] {
	case 0xff:
		return nil, mysqlErrPacket(head)
	case 0x00:
		return nil, nil // OK, no result set
	}
	ncols, _, ok := lenEncInt(head)
	if !ok || ncols > 256 {
		return nil, fmt.Errorf("mysql: bad column count")
	}
	for i := uint64(0); i < ncols; i++ {
		if _, err := wire.readPacket(); err != nil {
			return nil, err
		}
	}
	end, err := wire.readPacket()
	if err != nil {
		return nil, err
	}
	if !isEOF(end) {
		return nil, fmt.Errorf("mysql: columns not terminated")
	}
	var rows [][]string
	for len(rows) < mysqlMaxRows {
		p, err := wire.readPacket()
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			return nil, fmt.Errorf("mysql: empty row packet")
		}
		if p[0] == 0xff {
			return nil, mysqlErrPacket(p)
		}
		if isEOF(p) {
			return rows, nil
		}
		row, ok := parseTextRow(p, int(ncols))
		if !ok {
			return nil, fmt.Errorf("mysql: malformed row")
		}
		rows = append(rows, row)
	}
	return nil, fmt.Errorf("mysql: result exceeds row cap")
}

func isEOF(p []byte) bool { return len(p) < 9 && len(p) > 0 && p[0] == 0xfe }

// lenEncInt decodes a length-encoded integer, returning the value, the
// bytes consumed and ok.
func lenEncInt(p []byte) (uint64, int, bool) {
	if len(p) == 0 {
		return 0, 0, false
	}
	switch p[0] {
	case 0xfb:
		return 0, 1, true // NULL marker; callers treat as empty
	case 0xfc:
		if len(p) < 3 {
			return 0, 0, false
		}
		return uint64(p[1]) | uint64(p[2])<<8, 3, true
	case 0xfd:
		if len(p) < 4 {
			return 0, 0, false
		}
		return uint64(p[1]) | uint64(p[2])<<8 | uint64(p[3])<<16, 4, true
	case 0xfe:
		if len(p) < 9 {
			return 0, 0, false
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v |= uint64(p[1+i]) << (8 * i)
		}
		return v, 9, true
	default:
		return uint64(p[0]), 1, true
	}
}

// lenEncStr decodes one length-encoded string field.
func lenEncStr(p []byte) (string, []byte, bool) {
	n, used, ok := lenEncInt(p)
	if !ok || uint64(len(p)-used) < n || n > mysqlMaxPacketBytes {
		return "", p, false
	}
	return string(p[used : used+int(n)]), p[used+int(n):], true
}

func mysqlLenEncBytes(b []byte) []byte {
	if len(b) < 251 {
		return append([]byte{byte(len(b))}, b...)
	}
	out := []byte{0xfc, byte(len(b)), byte(len(b) >> 8)}
	return append(out, b...)
}

// parseTextRow decodes one text-protocol row of exactly n columns.
func parseTextRow(p []byte, n int) ([]string, bool) {
	row := make([]string, 0, n)
	rest := p
	for i := 0; i < n; i++ {
		if len(rest) > 0 && rest[0] == 0xfb {
			row = append(row, "")
			rest = rest[1:]
			continue
		}
		v, next, ok := lenEncStr(rest)
		if !ok {
			return nil, false
		}
		row = append(row, v)
		rest = next
	}
	return row, true
}

// auditMySQL runs the three tiers for one open port whose banner parsed
// as a MySQL greeting. Passive findings always; authenticated
// enumeration when o.Auth carries a login for this host:port; the
// CVE-2012-2122 probe when o.Intrusive and the version is in an
// affected family. Returns the intrusive login attempts made.
// Ordinary failures (wrong password, unreadable tables, closed
// stream) skip quietly; only safety refusals and emit errors return.
func (e *Engine) auditMySQL(ctx context.Context, dialer *safety.Dialer, host string, loc, assetKey string, g mysqlGreeting, o engine.Options, red *safety.Redactor, emit engine.EmitFunc) (probes int, err error) {
	flavour := "MySQL"
	if g.MariaDB {
		flavour = "MariaDB"
	}
	summary := fmt.Sprintf("flavour=%s version=%q protocol=10 auth_plugin=%q tls_capable=%v",
		flavour, g.Version, g.AuthPlugin, g.TLSCapable())
	mk := func(id string) domain.Finding {
		f := e.rules.NewFinding(id, assetKey, loc, domain.Confirmed)
		f.Evidence = []domain.Evidence{red.TextEvidence("mysql-greeting", loc, summary)}
		return f
	}
	f := mk("net.mysql.version")
	f.Title = fmt.Sprintf("%s server %s", flavour, g.Version)
	if err := emit(f); err != nil {
		return 0, err
	}
	if !g.TLSCapable() {
		f := mk("net.mysql.no-tls")
		f.Title = fmt.Sprintf("%s server does not offer TLS", flavour)
		if err := emit(f); err != nil {
			return 0, err
		}
	}
	if g.AuthPlugin == mysqlAuthOld {
		if err := emit(mk("net.mysql.legacy-auth")); err != nil {
			return 0, err
		}
	}

	if o.Auth.HasDBCredentials() {
		if err := e.mysqlEnumerate(ctx, dialer, host, loc, assetKey, o, red, emit); err != nil {
			return 0, err
		}
	}
	if o.Intrusive && mysqlCVEFamily(g.Version) {
		ok, tried, err := e.mysqlCVEProbe(ctx, dialer, loc, o.Log)
		probes += tried
		if err != nil {
			return probes, err
		}
		if ok {
			f := e.rules.NewFinding("net.mysql.cve-2012-2122", assetKey, loc, domain.Confirmed)
			f.Title = "MySQL authentication bypass (CVE-2012-2122)"
			f.Evidence = []domain.Evidence{red.TextEvidence("mysql-cve-probe", loc,
				fmt.Sprintf("wrong-password login as %q accepted after %d attempts; server version %q",
					mysqlCVEUser, tried, g.Version))}
			if err := emit(f); err != nil {
				return probes, err
			}
		}
	}
	return probes, nil
}

// mysqlEnumerate logs in with the --auth-file login (released only for
// this exact host:port) and runs the read-only allowlist. A rejected
// login or unreadable table skips quietly with a log line: the
// credentials are the caller's, and a wrong password is not a finding.
func (e *Engine) mysqlEnumerate(ctx context.Context, dialer *safety.Dialer, host, loc, assetKey string, o engine.Options, red *safety.Redactor, emit engine.EmitFunc) error {
	user, pass, ok := o.Auth.WithOrigin(loc).DBCredentials(loc)
	if !ok {
		return nil
	}
	conn, err := dialer.DialContext(ctx, "tcp", loc)
	if err != nil {
		return refusalOnly(err)
	}
	defer conn.Close() //nolint:errcheck // session done; findings already emitted
	if err := mysqlLogin(conn, mysqlServerName(host), user, pass); err != nil {
		var ae *mysqlAuthError
		if errors.As(err, &ae) || safety.IsRefusal(err) {
			mysqlLog(o.Log, "mysql authenticated enumeration skipped: login rejected", "loc", loc)
			return refusalOnly(err)
		}
		mysqlLog(o.Log, "mysql authenticated enumeration skipped", "loc", loc, "err", err.Error())
		return nil
	}
	wire := &mysqlWire{conn: conn}
	if err := e.mysqlAuditVariables(wire, loc, assetKey, red, emit); err != nil {
		return err
	}
	if err := e.mysqlAuditDatabases(wire, loc, assetKey, red, emit); err != nil {
		return err
	}
	return e.mysqlAuditAccounts(wire, loc, assetKey, red, emit)
}

// mysqlServerName returns the TLS server name: empty for IP literals
// (no SNI), the hostname otherwise.
func mysqlServerName(host string) string {
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsValid() {
		return ""
	}
	return host
}

func mysqlLog(log *slog.Logger, msg string, args ...any) {
	if log != nil {
		log.Info(msg, args...)
	}
}

// mysqlAuditVariables reads SHOW GLOBAL VARIABLES and flags insecure
// settings. Unreadable output skips quietly.
func (e *Engine) mysqlAuditVariables(wire *mysqlWire, loc, assetKey string, red *safety.Redactor, emit engine.EmitFunc) error {
	rows, err := mysqlQuery(wire, mysqlQVariables)
	if err != nil {
		return mysqlQuerySkip(err)
	}
	vars := map[string]string{}
	for _, r := range rows {
		if len(r) >= 2 {
			vars[strings.ToLower(r[0])] = r[1]
		}
	}
	if v, ok := vars["local_infile"]; ok && (strings.EqualFold(v, "ON") || v == "1") {
		f := e.rules.NewFinding("net.mysql.local-infile", assetKey, loc, domain.Confirmed)
		f.Evidence = []domain.Evidence{red.TextEvidence("mysql-variables", loc, "local_infile="+v)}
		if err := emit(f); err != nil {
			return err
		}
	}
	return nil
}

var mysqlSystemDBs = map[string]bool{"mysql": true, "information_schema": true, "performance_schema": true, "sys": true}

// mysqlAuditDatabases lists user databases (the mysql-databases
// equivalent). Database names are inventory, not secrets.
func (e *Engine) mysqlAuditDatabases(wire *mysqlWire, loc, assetKey string, red *safety.Redactor, emit engine.EmitFunc) error {
	rows, err := mysqlQuery(wire, mysqlQDatabases)
	if err != nil {
		return mysqlQuerySkip(err)
	}
	var user []string
	for _, r := range rows {
		if len(r) >= 1 && !mysqlSystemDBs[strings.ToLower(r[0])] {
			user = append(user, r[0])
		}
	}
	f := e.rules.NewFinding("net.mysql.databases", assetKey, loc, domain.Confirmed)
	names := strings.Join(user, ", ")
	if len(user) > 50 {
		names = strings.Join(user[:50], ", ") + fmt.Sprintf(", …and %d more", len(user)-50)
	}
	if names == "" {
		names = "(no user databases)"
	}
	switch {
	case len(user) == 1:
		f.Title = fmt.Sprintf("1 user database: %s", names)
	case len(user) <= 3:
		f.Title = fmt.Sprintf("%d user databases: %s", len(user), names)
	default:
		f.Title = fmt.Sprintf("%d user databases", len(user))
	}
	f.Evidence = []domain.Evidence{red.TextEvidence("mysql-databases", loc, names)}
	return emit(f)
}

// mysqlAuditAccounts reads mysql.user (new then legacy column layout)
// and flags remote root, anonymous and empty-password accounts. A
// login without SELECT on mysql.* skips quietly: absence of privilege
// is not a finding.
func (e *Engine) mysqlAuditAccounts(wire *mysqlWire, loc, assetKey string, red *safety.Redactor, emit engine.EmitFunc) error {
	rows, err := mysqlQuery(wire, mysqlQUsers)
	if err != nil {
		var ae *mysqlAuthError
		if errors.As(err, &ae) && (ae.Errno == mysqlErrNoColumn || ae.Errno == mysqlErrNoTable) {
			rows, err = mysqlQuery(wire, mysqlQUsersOld)
		}
		if err != nil {
			return mysqlQuerySkip(err)
		}
	}
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		user, host, auth, plugin := r[0], r[1], r[2], r[3]
		remote := mysqlRemoteHost(host)
		account := user + "@" + host
		at := func(id string) domain.Finding {
			f := e.rules.NewFinding(id, assetKey, loc+"/"+account, domain.Confirmed)
			f.Evidence = []domain.Evidence{red.TextEvidence("mysql-user", loc, "account="+account+" plugin="+plugin)}
			return f
		}
		if user == "" {
			f := at("net.mysql.anonymous-user")
			if !remote {
				f.Severity = domain.Medium
			}
			if err := emit(f); err != nil {
				return err
			}
			continue
		}
		if strings.EqualFold(user, "root") && remote {
			if err := emit(at("net.mysql.remote-root")); err != nil {
				return err
			}
		}
		if auth == "" && remote && mysqlPasswordPlugin(plugin) {
			if err := emit(at("net.mysql.empty-password")); err != nil {
				return err
			}
		}
		if plugin == mysqlAuthOld {
			if err := emit(at("net.mysql.legacy-auth")); err != nil {
				return err
			}
		}
	}
	return nil
}

// mysqlQuerySkip converts expected query failures (denied, missing
// table) into a quiet skip; emit errors still propagate via the caller.
func mysqlQuerySkip(err error) error {
	var ae *mysqlAuthError
	if errors.As(err, &ae) {
		return nil
	}
	// Transport and protocol failures mid-session: the session is
	// over, but the scan is not failed by one unreadable table.
	return nil
}

// mysqlRemoteHost reports whether an account host part is reachable
// from the network (anything but loopback names/addresses).
func mysqlRemoteHost(host string) bool {
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "", "localhost", "127.0.0.1", "::1":
		return false
	}
	return true
}

// mysqlPasswordPlugin reports whether an empty authentication string
// means "no password" for this plugin. Socket and external plugins
// authenticate elsewhere, so their empty strings are not findings.
func mysqlPasswordPlugin(plugin string) bool {
	switch plugin {
	case mysqlAuthNative, mysqlAuthSHA2, mysqlAuthSHA256, mysqlAuthOld, "":
		return true
	}
	return false
}

// mysqlCVEProbe attempts wrong-password logins as mysqlCVEUser until one
// succeeds, the attempt budget is spent, or the server stops answering
// cleanly. Success is only possible through the CVE-2012-2122 memcmp
// fail-open: the password is random per attempt and never a guess at a
// real credential. Returns success, attempts made, and only safety
// refusals as errors.
func (e *Engine) mysqlCVEProbe(ctx context.Context, dialer *safety.Dialer, loc string, log *slog.Logger) (bool, int, error) {
	tried := 0
	consecErr := 0
	for tried < mysqlCVEAttempts {
		if ctx.Err() != nil {
			return false, tried, ctx.Err()
		}
		tried++
		conn, err := dialer.DialContext(ctx, "tcp", loc)
		if err != nil {
			if safety.IsRefusal(err) {
				return false, tried, err
			}
			if consecErr++; consecErr >= mysqlMaxConsecErr {
				mysqlLog(log, "mysql CVE-2012-2122 probe aborted: server stopped answering", "loc", loc, "tried", tried)
				return false, tried, nil
			}
			continue
		}
		ok := mysqlTryLogin(conn, loc)
		conn.Close() //nolint:errcheck // attempt done; outcome already decided
		if ok {
			return true, tried, nil
		}
		consecErr = 0
	}
	return false, tried, nil
}

// mysqlTryLogin makes one wrong-password login attempt. True means the
// server accepted it (the bypass); anything else — rejection, protocol
// refusal, transport failure — is false, never an error.
func mysqlTryLogin(conn net.Conn, loc string) bool {
	pass := make([]byte, mysqlProbePassword)
	if _, err := rand.Read(pass); err != nil {
		return false
	}
	host, _, err := net.SplitHostPort(loc)
	if err != nil {
		host = loc
	}
	if err := mysqlLogin(conn, mysqlServerName(host), mysqlCVEUser, hex.EncodeToString(pass)); err != nil {
		return false
	}
	return true
}
