package iac

import (
	"strings"
)

var dockerRuleIDs = []string{"iac.docker.no-user", "iac.docker.add-url", "iac.docker.latest-tag", "iac.docker.secret-in-env"}

// instruction is one logical Dockerfile line after continuation joining.
type instruction struct {
	cmd  string // upper-case
	args string
	line int // line of the first physical line
}

// parseDockerfile joins backslash continuations, drops comments and
// parser directives, and splits each instruction into command + args.
func parseDockerfile(content []byte) []instruction {
	var out []instruction
	var cur strings.Builder
	curLine := 0
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" {
			return
		}
		cmd, args, _ := strings.Cut(s, " ")
		out = append(out, instruction{cmd: strings.ToUpper(cmd), args: strings.TrimSpace(args), line: curLine})
	}
	for i, raw := range strings.Split(string(content), "\n") {
		l := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(l)
		if cur.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			curLine = i + 1
		} else if strings.HasPrefix(trimmed, "#") {
			continue // comments are allowed inside continuations
		}
		if strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(trimmed)
		flush()
	}
	flush()
	return out
}

// checkDockerfile runs the Dockerfile rules over one file.
func checkDockerfile(file string, content []byte, em *emitter) error {
	ins := parseDockerfile(content)
	if len(ins) == 0 {
		return nil
	}
	stages := map[string]bool{}
	lastFrom, userAfterLastFrom := -1, false
	for i, in := range ins {
		switch in.cmd {
		case "FROM":
			lastFrom, userAfterLastFrom = i, false
			fields := strings.Fields(in.args)
			image := ""
			for _, f := range fields {
				if !strings.HasPrefix(f, "--") {
					image = f
					break
				}
			}
			for j, f := range fields {
				if strings.EqualFold(f, "AS") && j+1 < len(fields) {
					stages[strings.ToLower(fields[j+1])] = true
				}
			}
			if image == "" || image == "scratch" || strings.HasPrefix(image, "$") || stages[strings.ToLower(image)] {
				continue
			}
			if isLatest(image) {
				if err := em.rule("iac.docker.latest-tag", file, in.line, "FROM "+in.args); err != nil {
					return err
				}
			}
		case "USER":
			u := strings.TrimSpace(in.args)
			if u != "" && u != "root" && u != "0" && !strings.HasPrefix(u, "0:") && !strings.HasPrefix(u, "root:") {
				userAfterLastFrom = true
			} else {
				userAfterLastFrom = false
			}
		case "ADD":
			for _, f := range strings.Fields(in.args) {
				lf := strings.ToLower(f)
				if strings.HasPrefix(lf, "http://") || strings.HasPrefix(lf, "https://") {
					if err := em.rule("iac.docker.add-url", file, in.line, "ADD "+in.args); err != nil {
						return err
					}
					break
				}
			}
		case "ENV", "ARG":
			for name, value := range envPairs(in.args) {
				if isSecretAssignment(name, value) {
					if err := em.secret("iac.docker.secret-in-env", file, in.line, in.cmd+" "+name, value); err != nil {
						return err
					}
				}
			}
		}
	}
	if lastFrom >= 0 && !userAfterLastFrom {
		return em.rule("iac.docker.no-user", file, ins[lastFrom].line, "final stage starts at FROM "+ins[lastFrom].args+" and has no USER instruction")
	}
	return nil
}

// isLatest reports whether an image reference has no tag/digest or :latest.
func isLatest(image string) bool {
	if strings.Contains(image, "@") {
		return false
	}
	name := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		name = image[i+1:]
	}
	_, tag, ok := strings.Cut(name, ":")
	return !ok || tag == "latest"
}

// envPairs parses `ENV K=V K2="V 2"` and the legacy `ENV K V` form, and
// `ARG K=V` / `ARG K`.
func envPairs(args string) map[string]string {
	out := map[string]string{}
	if !strings.Contains(args, "=") {
		k, v, _ := strings.Cut(args, " ")
		out[k] = unquote(strings.TrimSpace(v))
		return out
	}
	for _, tok := range splitQuoted(args) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			out[tok] = ""
			continue
		}
		out[k] = unquote(v)
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// splitQuoted splits on spaces outside quotes.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
