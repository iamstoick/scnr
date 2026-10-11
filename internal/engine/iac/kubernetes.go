package iac

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iamstoick/scnr/internal/engine"
)

var k8sRuleIDs = []string{"iac.k8s.privileged", "iac.k8s.host-namespace", "iac.k8s.no-resource-limits", "iac.k8s.run-as-root", "iac.k8s.secret-in-env"}

// Caps on a manifest document: a hostile YAML file is still just a file,
// but nested aliases can expand to far more nodes than bytes. yaml.v3
// refuses excessive aliasing on its own; the walk below is the backstop.
const (
	maxYAMLNodes = 200_000
	maxYAMLDepth = 64
	maxYAMLDocs  = 200
)

var (
	k8sAPIRe  = regexp.MustCompile(`(?m)^apiVersion:\s*\S+`)
	k8sKindRe = regexp.MustCompile(`(?m)^kind:\s*\S+`)
)

// looksLikeK8s is a cheap content test before parsing: top-level apiVersion
// and kind, and not a Helm template.
func looksLikeK8s(content []byte) bool {
	if len(content) > MaxIaCFileBytes || bytes.Contains(content, []byte("{{")) {
		return false
	}
	return k8sAPIRe.Match(content) && k8sKindRe.Match(content)
}

// podSpecPaths maps a kind to the path of its pod spec.
var podSpecPaths = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
}

// checkKubernetes parses every document in the file and runs the pod rules.
// yaml.v3 recurses per nesting level, so the depth is measured on the bytes
// first; a file past engine.MaxNestingDepth is skipped unparsed (counted in
// the RuleFileSkipped note). countNodes below is the post-parse backstop.
func checkKubernetes(file string, content []byte, em *emitter) error {
	if engine.YAMLDepth(content, engine.MaxNestingDepth) > engine.MaxNestingDepth {
		em.skipped = append(em.skipped, file)
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	for docs := 0; docs < maxYAMLDocs; docs++ {
		var root yaml.Node
		err := dec.Decode(&root)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return nil // malformed YAML is not a finding; skip the file
		}
		if countNodes(&root, 0) < 0 {
			return nil // too deep or too large
		}
		doc := &root
		if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
			doc = doc.Content[0]
		}
		kind := scalar(child(doc, "kind"))
		p, ok := podSpecPaths[kind]
		if !ok {
			continue
		}
		spec := doc
		for _, k := range p {
			spec = child(spec, k)
			if spec == nil {
				break
			}
		}
		if spec == nil {
			continue
		}
		if err := checkPodSpec(file, kind, spec, em); err != nil {
			return err
		}
	}
	return nil
}

// countNodes returns the node count, or -1 when caps are exceeded.
func countNodes(n *yaml.Node, depth int) int {
	if depth > maxYAMLDepth {
		return -1
	}
	total := 1
	for _, c := range n.Content {
		sub := countNodes(c, depth+1)
		if sub < 0 {
			return -1
		}
		total += sub
		if total > maxYAMLNodes {
			return -1
		}
	}
	return total
}

// child returns the value node for key in a mapping node (aliases resolved
// one level; yaml.v3 already bounded alias expansion during decode).
func child(n *yaml.Node, key string) *yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return deref(n.Content[i+1])
		}
	}
	return nil
}

func deref(n *yaml.Node) *yaml.Node {
	for hops := 0; n != nil && n.Kind == yaml.AliasNode && hops < 8; hops++ {
		n = n.Alias
	}
	return n
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func isTrue(n *yaml.Node) bool { return strings.EqualFold(scalar(n), "true") }

func items(n *yaml.Node) []*yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, deref(c))
	}
	return out
}

func checkPodSpec(file, kind string, spec *yaml.Node, em *emitter) error {
	for _, ns := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if v := child(spec, ns); isTrue(v) {
			if err := em.rule("iac.k8s.host-namespace", file, v.Line, kind+" spec."+ns+": true"); err != nil {
				return err
			}
		}
	}
	podSC := child(spec, "securityContext")
	podNonRoot := isTrue(child(podSC, "runAsNonRoot")) || nonZero(scalar(child(podSC, "runAsUser")))
	for _, list := range []string{"containers", "initContainers"} {
		for _, c := range items(child(spec, list)) {
			if c == nil || c.Kind != yaml.MappingNode {
				continue // not a container object (e.g. an alias-expanded sequence)
			}
			name := scalar(child(c, "name"))
			if name == "" {
				name = list
			}
			line := c.Line
			sc := child(c, "securityContext")
			if v := child(sc, "privileged"); isTrue(v) {
				if err := em.rule("iac.k8s.privileged", file, v.Line, "container "+name+" securityContext.privileged: true"); err != nil {
					return err
				}
			}
			if !podNonRoot && !isTrue(child(sc, "runAsNonRoot")) && !nonZero(scalar(child(sc, "runAsUser"))) {
				if err := em.rule("iac.k8s.run-as-root", file, line, "container "+name+": runAsNonRoot not set"); err != nil {
					return err
				}
			}
			limits := child(child(c, "resources"), "limits")
			if child(limits, "memory") == nil || child(limits, "cpu") == nil {
				if err := em.rule("iac.k8s.no-resource-limits", file, line, "container "+name+": resources.limits missing cpu and/or memory"); err != nil {
					return err
				}
			}
			for _, env := range items(child(c, "env")) {
				n, v := scalar(child(env, "name")), child(env, "value")
				if v != nil && isSecretAssignment(n, scalar(v)) {
					if err := em.secret("iac.k8s.secret-in-env", file, v.Line, "container "+name+" env "+n, scalar(v)); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func nonZero(s string) bool { return s != "" && s != "0" }
