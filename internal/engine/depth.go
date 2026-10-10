package engine

// MaxNestingDepth bounds how deeply a file may nest before a recursive
// descent parser (hclsyntax, yaml.v3) is allowed to see it. Both libraries
// recurse once per nesting level and a Go stack overflow is fatal and not
// recoverable, so the check happens on the raw bytes, before parsing. Real
// configuration rarely nests beyond a dozen levels; 100 leaves ample room.
const MaxNestingDepth = 100

// BracketDepth returns the deepest nesting of (, [ and { in content,
// clamped to limit+1: scanning stops as soon as the limit is exceeded.
// Quoting is ignored on purpose (a bracket inside a string still counts),
// which can only make the result larger, so a caller that skips a file on
// depth > limit errs towards skipping, never towards parsing. HCL's
// template interpolations (${ and %{) end in a brace and are counted by it.
func BracketDepth(content []byte, limit int) int {
	depth, deepest := 0, 0
	for _, c := range content {
		switch c {
		case '(', '[', '{':
			depth++
			if depth > deepest {
				deepest = depth
				if deepest > limit {
					return limit + 1
				}
			}
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return deepest
}

// YAMLDepth returns the deepest nesting a YAML document can express in
// content, clamped to limit+1. Two constructs nest without consuming
// indentation: flow collections ([ and {) and block indicators chained on
// one line ("- - - x", "? ? k"). Indentation-based nesting needs a longer
// line per level, so a file of n bytes cannot nest deeper than about
// sqrt(2n) that way, well under limit for the file sizes scnr reads. As
// with BracketDepth, quoting and comments are ignored (over-approximation).
func YAMLDepth(content []byte, limit int) int {
	deepest := 0
	flow := 0 // running [ { depth across lines
	start := 0
	for start <= len(content) {
		end := start
		for end < len(content) && content[end] != '\n' {
			end++
		}
		line := content[start:end]
		start = end + 1
		i := 0
		for i < len(line) && line[i] == ' ' {
			i++
		}
		chain := 0
		for i+1 < len(line) && (line[i] == '-' || line[i] == '?') && line[i+1] == ' ' {
			chain++
			i += 2
		}
		if flow+chain > deepest {
			deepest = flow + chain
			if deepest > limit {
				return limit + 1
			}
		}
		for ; i < len(line); i++ {
			switch line[i] {
			case '[', '{':
				flow++
				if flow+chain > deepest {
					deepest = flow + chain
					if deepest > limit {
						return limit + 1
					}
				}
			case ']', '}':
				if flow > 0 {
					flow--
				}
			}
		}
	}
	return deepest
}
