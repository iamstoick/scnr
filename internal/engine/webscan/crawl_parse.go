package webscan

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// rawLink is one extracted anchor: href plus its clipped text.
type rawLink struct {
	href string
	text string
}

// maxLinkText caps collected anchor text per link.
const maxLinkText = 200

// extractLinks parses body and returns the effective base URL (page URL,
// or <base href> when present), every anchor href with its text, and
// every form (action, method, field names only).
func extractLinks(body []byte, pageURL *url.URL) (base *url.URL, links []rawLink, forms []Form) {
	base = pageURL
	baseSeen := false
	z := html.NewTokenizer(strings.NewReader(string(body)))
	var cur *rawLink
	var curForm *Form
	inForm := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if cur != nil {
				links = append(links, *cur)
			}
			if curForm != nil {
				forms = append(forms, *curForm)
			}
			return base, links, forms
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch string(name) {
			case "base":
				if baseSeen {
					continue
				}
				baseSeen = true
				if hasAttr {
					for {
						k, v, more := z.TagAttr()
						if string(k) == "href" {
							if u, err := pageURL.Parse(strings.TrimSpace(string(v))); err == nil {
								base = u
							}
						}
						if !more {
							break
						}
					}
				}
			case "a":
				if cur != nil {
					links = append(links, *cur)
				}
				cur = &rawLink{}
				if hasAttr {
					for {
						k, v, more := z.TagAttr()
						if string(k) == "href" {
							cur.href = strings.TrimSpace(string(v))
						}
						if !more {
							break
						}
					}
				}
				if tt == html.SelfClosingTagToken {
					links = append(links, *cur)
					cur = nil
				}
			case "form":
				if curForm != nil {
					forms = append(forms, *curForm)
				}
				curForm = &Form{Method: "get"}
				inForm = true
				if hasAttr {
					for {
						k, v, more := z.TagAttr()
						switch string(k) {
						case "action":
							curForm.Action = strings.TrimSpace(string(v))
						case "method":
							curForm.Method = strings.ToLower(strings.TrimSpace(string(v)))
						}
						if !more {
							break
						}
					}
				}
				if curForm.Method != "get" && curForm.Method != "post" {
					curForm.Method = "post" // unknown methods are never submitted
				}
				if tt == html.SelfClosingTagToken {
					forms = append(forms, *curForm)
					curForm = nil
					inForm = false
				}
			case "input", "select", "textarea":
				if !inForm || curForm == nil || !hasAttr {
					continue
				}
				for {
					k, v, more := z.TagAttr()
					// Field names only: values and hidden tokens are
					// never recorded.
					if string(k) == "name" && strings.TrimSpace(string(v)) != "" {
						curForm.Fields = append(curForm.Fields, strings.TrimSpace(string(v)))
					}
					if !more {
						break
					}
				}
			}
		case html.TextToken:
			if cur != nil && len(cur.text) < maxLinkText {
				cur.text += string(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "a":
				if cur != nil {
					links = append(links, *cur)
					cur = nil
				}
			case "form":
				if curForm != nil {
					forms = append(forms, *curForm)
					curForm = nil
				}
				inForm = false
			}
		}
	}
}

// resolveLink resolves href against base. It returns nil for empty,
// fragment-only, protocol-relative and non-HTTP(S) references —
// javascript:, data: and mailto: never become crawl candidates.
func resolveLink(base *url.URL, href string) *url.URL {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "//") {
		return nil
	}
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "mailto:") {
		return nil
	}
	u, err := base.Parse(href)
	if err != nil {
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	return u
}

// originID normalises scheme, host and effective port for same-origin
// comparison.
func originID(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if port == "" {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	return scheme + "://" + host + ":" + port
}

func stripFragment(u *url.URL) *url.URL {
	cp := *u
	cp.Fragment = ""
	return &cp
}

// collapseNumerics folds all-digit path segments to {n} for the collapse
// dedupe key (/items/123 -> /items/{n}); alphanumeric segments keep
// their identity.
func collapseNumerics(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s != "" && isDigits(s) {
			segs[i] = "{n}"
		}
	}
	return strings.Join(segs, "/")
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// crawlKey returns the exact dedupe key (path + sorted parameter names,
// values ignored), the numeric-collapsed variant, and the param names.
func crawlKey(u *url.URL) (key, fold string, params []string) {
	params = queryParamNames(u)
	key = u.Path + "\x00" + strings.Join(params, "\x00")
	fold = collapseNumerics(u.Path) + "\x00" + strings.Join(params, "\x00")
	return key, fold, params
}

// queryParamNames returns the sorted decoded names of a URL's query
// parameters (blank names dropped).
func queryParamNames(u *url.URL) []string {
	var out []string
	seen := map[string]bool{}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		name, _, _ := strings.Cut(pair, "=")
		if name == "" {
			continue
		}
		if dec, err := url.QueryUnescape(name); err == nil {
			name = dec
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// formGetURL turns a method=get form into a discovery URL: the action
// with the field names as empty parameters.
func formGetURL(page *url.URL, f Form) *url.URL {
	action := strings.TrimSpace(f.Action)
	var u *url.URL
	var err error
	if action == "" {
		cp := *page
		u = &cp
	} else {
		if u, err = page.Parse(action); err != nil {
			return nil
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	q := u.Query()
	for _, name := range f.Fields {
		if name != "" && q.Get(name) == "" {
			q.Set(name, "")
		}
	}
	u.RawQuery = q.Encode()
	return stripFragment(u)
}

// destructiveMatch reports whether rawURL (raw and percent-decoded) or
// text trips the deny list.
func destructiveMatch(deny *regexp.Regexp, rawURL, text string) bool {
	if deny.MatchString(rawURL) || deny.MatchString(text) {
		return true
	}
	if dec, err := url.PathUnescape(rawURL); err == nil && dec != rawURL {
		return deny.MatchString(dec)
	}
	return false
}

// clippedText trims anchor text for the inventory record.
func clippedText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxLinkText {
		s = s[:maxLinkText]
	}
	return s
}

// Robots is the parsed Disallow set for User-agent * and scnr.
type Robots struct {
	disallow []string
}

// parseRobots parses a robots.txt body. Only groups naming User-agent *
// or scnr contribute Disallow lines; an empty Disallow allows all.
func parseRobots(body []byte) *Robots {
	r := &Robots{}
	groupMatch := false
	inRules := false // a rule line since the last User-agent line
	for _, line := range strings.Split(string(body), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		field = strings.ToLower(strings.TrimSpace(field))
		value = strings.TrimSpace(value)
		switch field {
		case "user-agent":
			if inRules {
				groupMatch, inRules = false, false // a new group starts
			}
			v := strings.ToLower(value)
			if v == "*" || v == "scnr" {
				groupMatch = true
			}
		case "disallow":
			inRules = true
			if groupMatch && value != "" {
				r.disallow = append(r.disallow, value)
			}
		default:
			inRules = true
		}
	}
	return r
}

// Disallowed reports whether path matches a Disallow prefix. A nil Robots
// (fetch failed) allows everything.
func (r *Robots) Disallowed(path string) bool {
	if r == nil {
		return false
	}
	for _, d := range r.disallow {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// readCapped reads at most max bytes of a response body and closes it.
func readRespCapped(resp *http.Response, max int64) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, max))
}
