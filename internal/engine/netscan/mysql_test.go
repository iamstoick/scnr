package netscan

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// mysqlTestCaps is the standard modern capability set (no TLS unless added).
const mysqlTestCaps = uint32(mysqlClientProtocol41 | mysqlClientSecureConn | mysqlClientPluginAuth)

// buildGreetingPayload assembles a HandshakeV10 payload for fixtures.
func buildGreetingPayload(version string, caps uint32, plugin string, scr []byte) []byte {
	out := []byte{10}
	out = append(out, version...)
	out = append(out, 0)
	out = append(out, 0x78, 0x56, 0x34, 0x12) // connection id
	out = append(out, scr[:8]...)
	out = append(out, 0) // filler
	out = append(out, byte(caps), byte(caps>>8))
	out = append(out, 33, 0x02, 0x00) // charset, status
	out = append(out, byte(caps>>16), byte(caps>>24))
	out = append(out, 21) // auth-plugin-data length
	out = append(out, make([]byte, 10)...)
	out = append(out, scr[8:20]...)
	out = append(out, 0) // NUL terminating part 2
	out = append(out, plugin...)
	out = append(out, 0)
	return out
}

func framePacket(seq byte, payload []byte) []byte {
	out := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	return append(out, payload...)
}

func testScramble() []byte {
	return []byte("abcdefghijklmnopqrst") // 20 bytes
}

func TestParseMySQLGreeting(t *testing.T) {
	scr := testScramble()
	full := func(payload []byte) []byte { return framePacket(0, payload) }
	cases := []struct {
		name      string
		raw       []byte
		wantOK    bool
		version   string
		mariadb   bool
		tls       bool
		plugin    string
		cveFamily bool
	}{
		{"mysql8 sha2 tls", full(buildGreetingPayload("8.0.36", mysqlTestCaps|mysqlClientSSL, mysqlAuthSHA2, scr)), true, "8.0.36", false, true, mysqlAuthSHA2, false},
		{"mysql55 native no tls", full(buildGreetingPayload("5.5.62", mysqlTestCaps, mysqlAuthNative, scr)), true, "5.5.62", false, false, mysqlAuthNative, true},
		{"mariadb", full(buildGreetingPayload("10.11.7-MariaDB-1:10.11.7", mysqlTestCaps|mysqlClientSSL, mysqlAuthNative, scr)), true, "10.11.7-MariaDB-1:10.11.7", true, true, mysqlAuthNative, false},
		{"mariadb55", full(buildGreetingPayload("5.5.68-MariaDB", mysqlTestCaps, mysqlAuthNative, scr)), true, "5.5.68-MariaDB", true, false, mysqlAuthNative, true},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.3\r\n"), false, "", false, false, "", false},
		{"empty", nil, false, "", false, false, "", false},
		{"short header", []byte{1, 2}, false, "", false, false, "", false},
		{"bad seq", framePacket(3, buildGreetingPayload("8.0.36", mysqlTestCaps, mysqlAuthNative, scr)), false, "", false, false, "", false},
		{"truncated", full(buildGreetingPayload("8.0.36", mysqlTestCaps, mysqlAuthNative, scr))[:20], false, "", false, false, "", false},
		{"proto9", func() []byte {
			p := buildGreetingPayload("8.0.36", mysqlTestCaps, mysqlAuthNative, scr)
			p[0] = 9
			return full(p)
		}(), false, "", false, false, "", false},
		{"no41caps", full(buildGreetingPayload("8.0.36", 0, mysqlAuthNative, scr)), false, "", false, false, "", false},
		{"bad version", full(buildGreetingPayload("not-a-version", mysqlTestCaps, mysqlAuthNative, scr)), false, "", false, false, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, ok := parseMySQLGreeting(c.raw)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if g.Version != c.version || g.MariaDB != c.mariadb || g.TLSCapable() != c.tls || g.AuthPlugin != c.plugin {
				t.Fatalf("parsed %+v", g)
			}
			if len(g.Scramble) != 20 || string(g.Scramble) != string(scr) {
				t.Fatalf("scramble %q", g.Scramble)
			}
			if mysqlCVEFamily(g.Version) != c.cveFamily {
				t.Fatalf("cveFamily=%v want %v", !c.cveFamily, c.cveFamily)
			}
		})
	}
}

func TestMySQLMajorMinor(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
		ok           bool
	}{
		{"8.0.36", 8, 0, true},
		{"5.5.68-MariaDB", 5, 5, true},
		{"10.11.7-MariaDB-1:10.11.7", 10, 11, true},
		{"5.7.44-log", 5, 7, true},
		{"8.0", 8, 0, true},
		{"garbage", 0, 0, false},
		{"8", 0, 0, false},
		{"8.x", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		major, minor, ok := mysqlMajorMinor(c.in)
		if major != c.major || minor != c.minor || ok != c.ok {
			t.Errorf("%q -> %d.%d,%v", c.in, major, minor, ok)
		}
	}
}

func TestMySQLTokenProperties(t *testing.T) {
	scr := testScramble()
	other := append([]byte(nil), scr...)
	other[0] ^= 0xff
	a := mysqlToken("s3cret", scr)
	if len(a) != 20 {
		t.Fatalf("token len %d", len(a))
	}
	if string(a) != string(mysqlToken("s3cret", scr)) {
		t.Fatal("token not deterministic")
	}
	if string(a) == string(mysqlToken("s3cret", other)) {
		t.Fatal("token ignores scramble")
	}
	if string(a) == string(mysqlToken("other", scr)) {
		t.Fatal("token ignores password")
	}
	if len(mysqlToken("", scr)) != 0 {
		t.Fatal("empty password must send empty response")
	}
}

func TestMySQLQueryAllowlist(t *testing.T) {
	if _, err := mysqlQuery(&mysqlWire{}, "SELECT * FROM mysql.user"); err == nil {
		t.Fatal("non-allowlisted query accepted")
	}
	if _, err := mysqlQuery(&mysqlWire{}, "DROP DATABASE x"); err == nil {
		t.Fatal("write query accepted")
	}
}

// fakeMySQLServer is a scriptable minimal server: greeting, one login
// policy, canned result sets. It counts connections so tests prove how
// many follow-up connections each tier makes.
type fakeMySQLServer struct {
	ln        net.Listener
	greeting  []byte // framed, seq 0
	scramble  []byte
	password  string // correct password; token verified when acceptAny is false
	acceptAny bool   // accept every login (CVE fail-open simulation counts attempts first)
	acceptAt  int    // when >0: reject until this login attempt, then accept
	rejectAll bool   // always reject logins
	queries   map[string]fakeResult

	mu        sync.Mutex
	conns     int
	logins    int
	seenUsers []string
}

type fakeResult struct {
	cols int
	rows [][]string
}

func startFakeMySQL(t *testing.T, cfg *fakeMySQLServer) (port int, stats *fakeMySQLServer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg.ln = ln
	if cfg.queries == nil {
		cfg.queries = map[string]fakeResult{}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go cfg.serve(c)
		}
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	fmt.Sscanf(ps, "%d", &p)
	return p, cfg
}

func (s *fakeMySQLServer) serve(conn net.Conn) {
	defer conn.Close()
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	wire := &mysqlWire{conn: conn}
	if _, err := conn.Write(s.greeting); err != nil {
		return
	}
	resp, err := wire.readPacket()
	if err != nil {
		return
	}
	user := fakeResponseUser(resp)
	s.mu.Lock()
	s.logins++
	n := s.logins
	s.seenUsers = append(s.seenUsers, user)
	s.mu.Unlock()
	ok := false
	switch {
	case s.acceptAny:
		ok = true
	case s.acceptAt > 0:
		ok = n >= s.acceptAt
	case s.rejectAll:
		ok = false
	default:
		ok = user != "" && s.password != "" && fakeVerifyToken(resp, s.password, s.scramble) ||
			user != "" && s.password == "" && fakeEmptyToken(resp)
	}
	if !ok {
		wire.writePacket([]byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'x'})
		return
	}
	wire.writePacket([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	for {
		p, err := wire.readPacket()
		if err != nil || len(p) == 0 || p[0] != 0x03 {
			return
		}
		r, found := s.queries[string(p[1:])]
		if !found {
			wire.writePacket([]byte{0xff, 0x46, 0x04, '#', '4', '2', '0', '0', '0', 'x'})
			continue
		}
		wire.writePacket([]byte{byte(r.cols)})
		for i := 0; i < r.cols; i++ {
			wire.writePacket([]byte{0x03, 'c', 'o', 'l'})
		}
		wire.writePacket([]byte{0xfe, 0x00, 0x00, 0x02, 0x00})
		for _, row := range r.rows {
			var pkt []byte
			for _, f := range row {
				pkt = append(pkt, mysqlLenEncBytes([]byte(f))...)
			}
			wire.writePacket(pkt)
		}
		wire.writePacket([]byte{0xfe, 0x00, 0x00, 0x02, 0x00})
	}
}

// fakeResponseUser extracts the username from a HandshakeResponse41.
func fakeResponseUser(resp []byte) string {
	if len(resp) < 32 {
		return ""
	}
	rest := resp[32:]
	name, _, ok := cstring(rest)
	if !ok {
		return ""
	}
	return name
}

// fakeVerifyToken recomputes the expected token with the same primitive
// the client uses (consistency check; the passive parser vectors above
// pin the wire format independently).
func fakeVerifyToken(resp []byte, password string, scr []byte) bool {
	if len(resp) < 32 {
		return false
	}
	rest := resp[32:]
	_, rest, ok := cstring(rest)
	if !ok || len(rest) == 0 {
		return false
	}
	n := int(rest[0])
	if n != 20 || len(rest) < 1+n {
		return false
	}
	return string(rest[1:1+n]) == string(mysqlToken(password, scr))
}

func fakeEmptyToken(resp []byte) bool {
	if len(resp) < 32 {
		return false
	}
	rest := resp[32:]
	_, rest, ok := cstring(rest)
	return ok && len(rest) > 0 && rest[0] == 0
}

func dbAuth(t *testing.T, user, pass string) *safety.AuthMaterial {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth.yaml")
	body := fmt.Sprintf("mysql:\n  user: %s\n  password: %q\n", user, pass)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := safety.LoadAuthFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mysqlTarget() domain.Target {
	return domain.Target{Raw: "127.0.0.1", Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}
}

func mysqlGreetingFixture(version string, caps uint32, plugin string) (framed, scr []byte) {
	scr = testScramble()
	return framePacket(0, buildGreetingPayload(version, caps, plugin, scr)), scr
}

// TestMySQLPassiveAudit proves tier 1: version findings from the banner
// bytes with zero follow-up connections (the server sees exactly the
// initial connect).
func TestMySQLPassiveAudit(t *testing.T) {
	framed, scr := mysqlGreetingFixture("8.0.36", mysqlTestCaps, mysqlAuthSHA2)
	port, stats := startFakeMySQL(t, &fakeMySQLServer{greeting: framed, scramble: scr, password: "x", rejectAll: true})
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	out := collect(t, e, mysqlTarget(), o)
	vers := out["net.mysql.version"]
	if len(vers) != 1 || vers[0].Title != "MySQL server 8.0.36" {
		t.Fatalf("version finding: %+v", vers)
	}
	if len(out["net.mysql.no-tls"]) != 1 {
		t.Fatalf("no-tls finding missing: %v", out)
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.conns != 1 || stats.logins != 0 {
		t.Fatalf("passive tier made follow-up connections: %+v", stats)
	}
}

// TestMySQLAuthenticatedEnumeration runs tier 2 end to end against the
// fake server and asserts every rule plus password hygiene.
func TestMySQLAuthenticatedEnumeration(t *testing.T) {
	framed, scr := mysqlGreetingFixture("8.0.36", mysqlTestCaps, mysqlAuthNative)
	const password = "s3cret-auditor-pw"
	port, stats := startFakeMySQL(t, &fakeMySQLServer{
		greeting: framed, scramble: scr, password: password,
		queries: map[string]fakeResult{
			mysqlQVariables: {cols: 2, rows: [][]string{{"local_infile", "ON"}, {"have_ssl", "NO"}, {"version", "8.0.36"}}},
			mysqlQDatabases: {cols: 1, rows: [][]string{{"mysql"}, {"information_schema"}, {"appdb"}, {"shop"}}},
			mysqlQUsers: {cols: 4, rows: [][]string{
				{"root", "%", "*A4B615731903872334083...", "mysql_native_password"},
				{"", "localhost", "", ""},
				{"app", "10.0.0.5", "", "mysql_native_password"},
				{"svc", "localhost", "", "auth_socket"},
				{"old", "%", "4abcd93d9d4c9d0d", "mysql_old_password"},
			}},
		},
	})
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	o.Auth = dbAuth(t, "auditor", password)
	out := collect(t, e, mysqlTarget(), o)

	if len(out["net.mysql.version"]) != 1 {
		t.Fatalf("version: %v", out)
	}
	if len(out["net.mysql.local-infile"]) != 1 {
		t.Fatalf("local-infile: %v", out)
	}
	dbs := out["net.mysql.databases"]
	if len(dbs) != 1 || !strings.Contains(dbs[0].Title, "2 user databases") {
		t.Fatalf("databases: %+v", dbs)
	}
	if len(out["net.mysql.remote-root"]) != 1 {
		t.Fatalf("remote-root: %v", out)
	}
	anon := out["net.mysql.anonymous-user"]
	if len(anon) != 1 || anon[0].Severity != domain.Medium {
		t.Fatalf("localhost anonymous should be medium: %+v", anon)
	}
	if len(out["net.mysql.empty-password"]) != 1 {
		t.Fatalf("empty-password: %v", out)
	}
	if len(out["net.mysql.legacy-auth"]) != 1 {
		t.Fatalf("legacy-auth: %v", out)
	}
	// Password hygiene: the secret appears nowhere in findings.
	for id, fs := range out {
		for _, f := range fs {
			blob := fmt.Sprintf("%s %s %+v", f.Title, f.Location, f.Evidence)
			if strings.Contains(blob, password) {
				t.Fatalf("password leaked in %s: %s", id, blob)
			}
		}
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.conns != 2 || stats.logins != 1 {
		t.Fatalf("want banner connect + 1 session, got %+v", stats)
	}
	if len(stats.seenUsers) != 1 || stats.seenUsers[0] != "auditor" {
		t.Fatalf("seen users: %v", stats.seenUsers)
	}
}

// TestMySQLWrongPasswordSkips proves a rejected login is a quiet skip,
// not a scan failure and not a finding.
func TestMySQLWrongPasswordSkips(t *testing.T) {
	framed, scr := mysqlGreetingFixture("8.0.36", mysqlTestCaps, mysqlAuthNative)
	port, _ := startFakeMySQL(t, &fakeMySQLServer{greeting: framed, scramble: scr, password: "correct-pw", rejectAll: true})
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	o.Auth = dbAuth(t, "auditor", "wrong-pw")
	out := collect(t, e, mysqlTarget(), o) // must not error
	if len(out["net.mysql.version"]) != 1 {
		t.Fatalf("passive findings must still emit: %v", out)
	}
	if len(out["net.mysql.databases"]) != 0 || len(out["net.mysql.remote-root"]) != 0 {
		t.Fatalf("no enumeration findings expected: %v", out)
	}
}

// TestMySQLCVEProbeSuccess simulates the fail-open bug (accept on the
// 5th login) and proves the critical finding plus probe accounting.
func TestMySQLCVEProbeSuccess(t *testing.T) {
	framed, scr := mysqlGreetingFixture("5.5.62", mysqlTestCaps, mysqlAuthNative)
	port, stats := startFakeMySQL(t, &fakeMySQLServer{greeting: framed, scramble: scr, acceptAt: 5})
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	o.Intrusive = true
	var gotStats engine.Stats
	o.Stats = func(s engine.Stats) { gotStats = s }
	out := collect(t, e, mysqlTarget(), o)
	cve := out["net.mysql.cve-2012-2122"]
	if len(cve) != 1 || cve[0].Severity != domain.Critical || cve[0].Confidence != domain.Confirmed {
		t.Fatalf("cve finding: %+v", cve)
	}
	if gotStats.Probes != 5 {
		t.Fatalf("stats probes=%d want 5", gotStats.Probes)
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.logins != 5 {
		t.Fatalf("logins=%d want 5", stats.logins)
	}
	if len(stats.seenUsers) == 0 || stats.seenUsers[0] != mysqlCVEUser {
		t.Fatalf("probe user: %v", stats.seenUsers)
	}
}

// TestMySQLCVEProbeNegative proves a patched server exhausts the full
// attempt budget with no finding and a bounded connection burst.
func TestMySQLCVEProbeNegative(t *testing.T) {
	framed, scr := mysqlGreetingFixture("5.5.62", mysqlTestCaps, mysqlAuthNative)
	port, stats := startFakeMySQL(t, &fakeMySQLServer{greeting: framed, scramble: scr, rejectAll: true})
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	o.Intrusive = true
	var gotStats engine.Stats
	o.Stats = func(s engine.Stats) { gotStats = s }
	out := collect(t, e, mysqlTarget(), o)
	if len(out["net.mysql.cve-2012-2122"]) != 0 {
		t.Fatalf("no CVE finding expected: %v", out)
	}
	if gotStats.Probes != mysqlCVEAttempts {
		t.Fatalf("stats probes=%d want %d", gotStats.Probes, mysqlCVEAttempts)
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.logins != mysqlCVEAttempts {
		t.Fatalf("logins=%d want %d", stats.logins, mysqlCVEAttempts)
	}
}

// TestMySQLCVEProbeSkippedModern proves the version gate: a modern
// greeting gets zero login attempts even with intrusive allowed.
func TestMySQLCVEProbeSkippedModern(t *testing.T) {
	framed, scr := mysqlGreetingFixture("8.0.36", mysqlTestCaps, mysqlAuthSHA2)
	port, stats := startFakeMySQL(t, &fakeMySQLServer{greeting: framed, scramble: scr, acceptAny: true})
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	o.Intrusive = true
	out := collect(t, e, mysqlTarget(), o)
	if len(out["net.mysql.cve-2012-2122"]) != 0 {
		t.Fatalf("no CVE finding expected: %v", out)
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.conns != 1 || stats.logins != 0 {
		t.Fatalf("modern server must see no logins: %+v", stats)
	}
}

// TestMySQLLoginRefusesUnsupportedPlugin proves fail-closed auth: the
// client sends nothing past a greeting whose plugin it cannot speak.
func TestMySQLLoginRefusesUnsupportedPlugin(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	framed, _ := mysqlGreetingFixture("8.0.36", mysqlTestCaps, "auth_socket")
	wrote := make(chan int, 1)
	go func() {
		defer close(wrote)
		if _, err := srv.Write(framed); err != nil {
			return
		}
		var one [1]byte
		n, _ := srv.Read(one[:]) // unblocks at EOF when the client gives up
		wrote <- n
	}()
	if err := mysqlLogin(cli, "", "auditor", "pw"); err == nil || !strings.Contains(err.Error(), "unsupported auth plugin") {
		t.Fatalf("login err: %v", err)
	}
	cli.Close()
	if n := <-wrote; n != 0 {
		t.Fatalf("client wrote %d bytes for unsupported plugin", n)
	}
}

// TestMySQLLoginRefusesCleartextWithoutTLS proves the password never
// goes out when full authentication is demanded over plaintext.
func TestMySQLLoginRefusesCleartextWithoutTLS(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	framed, _ := mysqlGreetingFixture("8.0.36", mysqlTestCaps, mysqlAuthSHA2)
	const password = "topsecret-cleartext"
	sawPassword := make(chan bool, 1)
	go func() {
		defer close(sawPassword)
		wire := &mysqlWire{conn: srv}
		if _, err := srv.Write(framed); err != nil {
			return
		}
		if _, err := wire.readPacket(); err != nil { // handshake response
			return
		}
		wire.writePacket([]byte{0x01}) // perform full authentication
		rest, _ := wire.readPacket()   // must be EOF: client refuses
		for _, chunk := range [][]byte{rest} {
			if strings.Contains(string(chunk), password) {
				sawPassword <- true
				return
			}
		}
		sawPassword <- false
	}()
	err := mysqlLogin(cli, "", "auditor", password)
	cli.Close()
	if err == nil || !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("login err: %v", err)
	}
	if saw := <-sawPassword; saw {
		t.Fatal("password sent over plaintext")
	}
}

func TestNetscanPlanDisclosesMySQL(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o := testOptions(t, []int{3306})
	plan, err := e.Plan(context.Background(), mysqlTarget(), o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.Summary, "mysql") {
		t.Fatalf("bare plan must not mention mysql: %q", plan.Summary)
	}
	o.Auth = dbAuth(t, "auditor", "pw")
	o.Intrusive = true
	plan, err = e.Plan(context.Background(), mysqlTarget(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Summary, `mysql authenticated enumeration as "auditor"`) {
		t.Fatalf("plan hides mysql auth: %q", plan.Summary)
	}
	if !strings.Contains(plan.Summary, "CVE-2012-2122") {
		t.Fatalf("plan hides CVE probe: %q", plan.Summary)
	}
	if plan.EstRequests != 1+mysqlCVEAttempts {
		t.Fatalf("EstRequests=%d", plan.EstRequests)
	}
	if strings.Contains(plan.Summary, "pw") {
		t.Fatalf("password in plan: %q", plan.Summary)
	}
}
