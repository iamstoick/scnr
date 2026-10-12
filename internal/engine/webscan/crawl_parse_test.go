package webscan

import (
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestExtractLinks(t *testing.T) {
	page := mustURL(t, "https://app.example/dir/page?a=1")
	body := `<html><head><base href="/base/"></head><body>` +
		`<a href="/x">ex</a>` +
		`<a href="rel">relative link</a>` +
		`<a href="https://evil.example/y">off origin</a>` +
		`<a href="//other.example/z">protocol relative</a>` +
		`<a href="javascript:alert(1)">js</a>` +
		`<a href="mailto:a@b">mail</a>` +
		`<a href="#frag">frag</a>` +
		`<a>no href</a>` +
		`<form action="/submit" method="post"><input name="u"><input name="pw" value="s3cr3t"><input type="hidden" name="tok" value="t0k"></form>` +
		`<form><select name="s"></select><textarea name="t"></textarea></form>` +
		`</body></html>`
	base, links, forms := extractLinks([]byte(body), page)
	if base.Path != "/base/" {
		t.Fatalf("base: %s", base)
	}
	var hrefs []string
	for _, l := range links {
		hrefs = append(hrefs, l.href)
	}
	joined := strings.Join(hrefs, " ")
	for _, want := range []string{"/x", "rel", "https://evil.example/y"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, hrefs)
		}
	}
	// Dangerous schemes are extracted raw but never resolve: the crawler
	// only follows URLs that survive resolveLink.
	for _, l := range links {
		lower := strings.ToLower(l.href)
		if strings.HasPrefix(l.href, "//") || strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(l.href, "mailto:") || strings.HasPrefix(l.href, "#") {
			if resolveLink(base, l.href) != nil {
				t.Errorf("resolved %q", l.href)
			}
		}
	}
	if len(forms) != 2 {
		t.Fatalf("forms: %+v", forms)
	}
	if forms[0].Action != "/submit" || forms[0].Method != "post" || strings.Join(forms[0].Fields, ",") != "u,pw,tok" {
		t.Fatalf("form0: %+v", forms[0])
	}
	// Values and hidden tokens never recorded.
	if strings.Contains(strings.Join(forms[0].Fields, ","), "s3cr3t") {
		t.Fatal("field value recorded")
	}
	if forms[1].Method != "get" || strings.Join(forms[1].Fields, ",") != "s,t" {
		t.Fatalf("form1: %+v", forms[1])
	}
}

func TestResolveLink(t *testing.T) {
	base := mustURL(t, "https://app.example/dir/")
	for raw, want := range map[string]string{
		"/abs": "https://app.example/abs", "rel": "https://app.example/dir/rel",
		"https://app.example/x": "https://app.example/x", "http://app.example/x": "http://app.example/x",
	} {
		u := resolveLink(base, raw)
		if u == nil || u.String() != want {
			t.Errorf("%q -> %v", raw, u)
		}
	}
	for _, raw := range []string{"", "#f", "//x/y", "javascript:x", "JAVASCRIPT:x", "data:text/plain,x", "mailto:a@b", "ftp://h/x", "http://[::1"} {
		if u := resolveLink(base, raw); u != nil {
			t.Errorf("%q -> %v", raw, u)
		}
	}
}

func TestOriginID(t *testing.T) {
	a := mustURL(t, "https://APP.example./x")
	b := mustURL(t, "https://app.example:443/y")
	c := mustURL(t, "http://app.example/")
	d := mustURL(t, "https://app.example:8443/")
	if originID(a) != originID(b) {
		t.Fatal("default port and case/trailing-dot should match")
	}
	if originID(a) == originID(c) || originID(a) == originID(d) {
		t.Fatal("scheme/port must differ")
	}
}

func TestCrawlKey(t *testing.T) {
	k1, _, _ := crawlKey(mustURL(t, "https://h/items?page=1&sort=a"))
	k2, _, _ := crawlKey(mustURL(t, "https://h/items?sort=b&page=2"))
	if k1 != k2 {
		t.Fatal("values and order must not matter")
	}
	k3, _, p := crawlKey(mustURL(t, "https://h/items?page=1&other=1"))
	if k1 == k3 || strings.Join(p, ",") != "other,page" {
		t.Fatalf("param names matter: %q %v", k3, p)
	}
	_, f1, _ := crawlKey(mustURL(t, "https://h/items/123"))
	_, f2, _ := crawlKey(mustURL(t, "https://h/items/456"))
	if f1 != f2 {
		t.Fatal("numeric segments must collapse")
	}
	_, f3, _ := crawlKey(mustURL(t, "https://h/items/abc"))
	if f1 == f3 {
		t.Fatal("alpha segments must not collapse")
	}
}

func TestQueryParamNames(t *testing.T) {
	got := queryParamNames(mustURL(t, "https://h/?b=1&a=2&b=3&=x&c"))
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("%v", got)
	}
}

func TestParseRobots(t *testing.T) {
	body := "User-agent: googlebot\nDisallow: /no-google\n\n" +
		"User-agent: *\nDisallow: /priv/\nDisallow: \n" +
		"User-agent: other\nDisallow: /other\n"
	r := parseRobots([]byte(body))
	if !r.Disallowed("/priv/x") || r.Disallowed("/pub") {
		t.Fatal("star group")
	}
	if r.Disallowed("/no-google") || r.Disallowed("/other") {
		t.Fatal("other groups leak")
	}
	// Multi-UA group latches on any match.
	r2 := parseRobots([]byte("User-agent: googlebot\nUser-agent: scnr\nDisallow: /s\n"))
	if !r2.Disallowed("/s") {
		t.Fatal("multi-UA group")
	}
	var nilR *Robots
	if nilR.Disallowed("/x") {
		t.Fatal("nil robots must allow")
	}
}

func TestDestructiveMatch(t *testing.T) {
	for _, u := range []string{"https://h/logout", "https://h/items/1/delete", "https://h/a?x=1&do=purge", "https://h/%6Cogout", "https://h/sign-out"} {
		if !destructiveMatch(DefaultDenyWords, u, "") {
			t.Errorf("missed %s", u)
		}
	}
	if !destructiveMatch(DefaultDenyWords, "https://h/page", "Please Logout") {
		t.Error("link text missed")
	}
	for _, u := range []string{"https://h/login", "https://h/formatting-guide", "https://h/cancelled-orders", "https://h/about"} {
		if destructiveMatch(DefaultDenyWords, u, "") {
			t.Errorf("false positive %s", u)
		}
	}
}
