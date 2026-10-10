// Package jsonschema is a deliberately small JSON Schema (draft-04/07)
// checker covering the keywords the SARIF 2.1.0 and CycloneDX 1.5 schemas
// use structurally. It exists so tests can validate our output against the
// published schema files in testdata without adding a dependency to the
// binary; it is not a general-purpose validator.
package jsonschema

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Validator checks documents against one root schema plus any sibling
// schema files it references by relative URL.
type Validator struct {
	root  map[string]any
	dir   string
	files map[string]map[string]any
	errs  []string
}

// Load reads the schema file at path; external $refs are resolved against
// files in the same directory.
func Load(path string) (*Validator, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("schema %s: %w", path, err)
	}
	return &Validator{root: root, dir: filepath.Dir(path), files: map[string]map[string]any{}}, nil
}

// Validate returns the list of violations (empty when valid).
func (v *Validator) Validate(doc []byte) ([]string, error) {
	var d any
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	s := &Validator{root: v.root, dir: v.dir, files: v.files}
	s.check(v.root, v.root, d, "$")
	return s.errs, nil
}

func (v *Validator) errf(path, format string, args ...any) {
	if len(v.errs) < 50 {
		v.errs = append(v.errs, path+": "+fmt.Sprintf(format, args...))
	}
}

// resolve returns the schema a $ref points at and the root document it
// lives in (so nested refs inside an external file resolve there).
func (v *Validator) resolve(cur map[string]any, ref string) (map[string]any, map[string]any) {
	file, frag, _ := strings.Cut(ref, "#")
	root := cur
	if file != "" {
		if strings.Contains(file, "/") || strings.Contains(file, "..") {
			return nil, nil // only sibling files by bare name
		}
		ext, ok := v.files[file]
		if !ok {
			b, err := os.ReadFile(filepath.Join(v.dir, file))
			if err != nil || json.Unmarshal(b, &ext) != nil {
				return nil, nil
			}
			v.files[file] = ext
		}
		root = ext
	}
	if frag == "" {
		return root, root
	}
	node := any(root)
	for _, part := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		m, ok := node.(map[string]any)
		if !ok {
			return nil, nil
		}
		node = m[part]
	}
	m, _ := node.(map[string]any)
	return m, root
}

func (v *Validator) check(root, sch map[string]any, val any, path string) {
	if ref, ok := sch["$ref"].(string); ok {
		target, troot := v.resolve(root, ref)
		if target == nil {
			v.errf(path, "unresolvable $ref %s", ref)
			return
		}
		v.check(troot, target, val, path)
		return
	}
	if t, ok := sch["type"]; ok && !typeMatches(t, val) {
		v.errf(path, "type %v, got %T", t, val)
		return
	}
	if enum, ok := sch["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if fmt.Sprint(e) == fmt.Sprint(val) {
				found = true
			}
		}
		if !found {
			v.errf(path, "%v not in enum", val)
		}
	}
	if c, ok := sch["const"]; ok && fmt.Sprint(c) != fmt.Sprint(val) {
		v.errf(path, "%v != const %v", val, c)
	}
	if all, ok := sch["allOf"].([]any); ok {
		for _, a := range all {
			if am, ok := a.(map[string]any); ok {
				v.check(root, am, val, path)
			}
		}
	}
	for _, kw := range []string{"anyOf", "oneOf"} {
		if alts, ok := sch[kw].([]any); ok {
			matched := 0
			for _, a := range alts {
				am, _ := a.(map[string]any)
				sub := &Validator{root: v.root, dir: v.dir, files: v.files}
				sub.check(root, am, val, path)
				if len(sub.errs) == 0 {
					matched++
				}
			}
			if matched == 0 || (kw == "oneOf" && matched != 1) {
				v.errf(path, "%s: %d alternatives matched", kw, matched)
			}
		}
	}
	switch x := val.(type) {
	case map[string]any:
		props, _ := sch["properties"].(map[string]any)
		if req, ok := sch["required"].([]any); ok {
			for _, r := range req {
				if _, ok := x[r.(string)]; !ok {
					v.errf(path, "missing required %q", r)
				}
			}
		}
		if deps, ok := sch["dependencies"].(map[string]any); ok {
			for k, d := range deps {
				if _, present := x[k]; !present {
					continue
				}
				if list, ok := d.([]any); ok {
					for _, need := range list {
						if _, ok := x[need.(string)]; !ok {
							v.errf(path, "%q requires %q", k, need)
						}
					}
				}
			}
		}
		addl, hasAddl := sch["additionalProperties"]
		for k, pv := range x {
			if ps, ok := props[k].(map[string]any); ok {
				v.check(root, ps, pv, path+"."+k)
				continue
			}
			if hasAddl {
				switch a := addl.(type) {
				case bool:
					if !a {
						v.errf(path, "additional property %q not allowed", k)
					}
				case map[string]any:
					v.check(root, a, pv, path+"."+k)
				}
			}
		}
	case []any:
		if items, ok := sch["items"].(map[string]any); ok {
			for i, it := range x {
				v.check(root, items, it, fmt.Sprintf("%s[%d]", path, i))
			}
		}
		if min, ok := sch["minItems"].(float64); ok && float64(len(x)) < min {
			v.errf(path, "fewer than %v items", min)
		}
		if u, ok := sch["uniqueItems"].(bool); ok && u {
			seen := map[string]bool{}
			for _, it := range x {
				b, _ := json.Marshal(it)
				if seen[string(b)] {
					v.errf(path, "duplicate item %s", b)
				}
				seen[string(b)] = true
			}
		}
	case string:
		if p, ok := sch["pattern"].(string); ok {
			if re, err := regexp.Compile(p); err == nil && !re.MatchString(x) {
				v.errf(path, "%q does not match %s", x, p)
			}
		}
		if min, ok := sch["minLength"].(float64); ok && float64(len([]rune(x))) < min {
			v.errf(path, "shorter than %v", min)
		}
		if max, ok := sch["maxLength"].(float64); ok && float64(len([]rune(x))) > max {
			v.errf(path, "longer than %v", max)
		}
	case float64:
		if min, ok := sch["minimum"].(float64); ok && x < min {
			v.errf(path, "%v < minimum %v", x, min)
		}
		if max, ok := sch["maximum"].(float64); ok && x > max {
			v.errf(path, "%v > maximum %v", x, max)
		}
	}
}

func typeMatches(t any, v any) bool {
	switch tt := t.(type) {
	case string:
		return typeIs(tt, v)
	case []any:
		for _, x := range tt {
			if typeIs(x.(string), v) {
				return true
			}
		}
	}
	return false
}

func typeIs(t string, v any) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	case "null":
		return v == nil
	}
	return false
}
