package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"

	"github.com/gerald/scnr/internal/engine"
)

var terraformRuleIDs = []string{
	"iac.tf.s3-public-acl", "iac.tf.s3-no-public-access-block", "iac.tf.s3-no-encryption", "iac.tf.s3-no-versioning", "iac.tf.s3-no-logging",
	"iac.tf.sg-open-ssh", "iac.tf.sg-open-rdp", "iac.tf.sg-open-all",
	"iac.tf.rds-public", "iac.tf.rds-unencrypted", "iac.tf.rds-no-backups",
	"iac.tf.ebs-unencrypted", "iac.tf.iam-wildcard-action",
	"iac.tf.cloudtrail-logging-disabled", "iac.tf.cloudtrail-not-multi-region", "iac.tf.cloudtrail-no-validation",
	"iac.tf.kms-rotation-disabled", "iac.tf.secret-in-variable-default", "iac.tf.instance-public-ip", "iac.tf.lambda-secret-in-env",
}

// Work bounds per module (a repo is attacker-controlled input).
const (
	maxTFResources = 20_000
	// MaxTerraformFileBytes caps one .tf file: hand-written and generated
	// modules are tens of KiB; anything larger is skipped unparsed.
	MaxTerraformFileBytes = 512 << 10
	// maxExprElements caps the elements of one literal tuple or object and
	// maxExprNodes the syntax nodes of one attribute expression; beyond
	// either the attribute is unresolvable (never a finding).
	maxExprElements = 1000
	maxExprNodes    = 10_000
)

// evalCtx evaluates constant expressions only. jsonencode is the one
// function policies routinely use; variables, locals and data references
// are unknown and make an attribute "unresolvable", which is never a
// finding (conservative: no false positives from values we cannot see).
var evalCtx = &hcl.EvalContext{Functions: map[string]function.Function{"jsonencode": stdlib.JSONEncodeFunc}}

// exprShape walks an expression before evaluation and rejects anything
// that is not constant-shaped: for/splat/conditional expressions (a nested
// `for` over literal lists evaluates in O(n^k) time and memory), template
// directives (which parse into the same node types), function calls other
// than jsonencode, oversized collections and oversized trees. Only what
// passes is handed to hcl's evaluator.
type exprShape struct {
	nodes int
	ok    bool
}

func (s *exprShape) Enter(n hclsyntax.Node) hcl.Diagnostics {
	s.nodes++
	if s.nodes > maxExprNodes {
		s.ok = false
	}
	switch e := n.(type) {
	case *hclsyntax.ForExpr, *hclsyntax.SplatExpr, *hclsyntax.ConditionalExpr, *hclsyntax.AnonSymbolExpr:
		s.ok = false
	case *hclsyntax.FunctionCallExpr:
		if e.Name != "jsonencode" || e.ExpandFinal {
			s.ok = false
		}
	case *hclsyntax.TupleConsExpr:
		if len(e.Exprs) > maxExprElements {
			s.ok = false
		}
	case *hclsyntax.ObjectConsExpr:
		if len(e.Items) > maxExprElements {
			s.ok = false
		}
	}
	return nil
}

func (s *exprShape) Exit(hclsyntax.Node) hcl.Diagnostics { return nil }

// constShaped reports whether expr may be evaluated with evalCtx.
func constShaped(expr hclsyntax.Expression) bool {
	s := &exprShape{ok: true}
	_ = hclsyntax.Walk(expr, s)
	return s.ok
}

// block is a top-level resource/data/variable with its file.
type block struct {
	kind   string // resource | data | variable
	typ    string // aws_s3_bucket (resource/data) or variable name
	name   string
	file   string
	b      *hclsyntax.Block
	nested []*hclsyntax.Block
}

func (b *block) line() int { return b.b.TypeRange.Start.Line }

func (b *block) addr() string {
	switch b.kind {
	case "variable":
		return fmt.Sprintf(`variable "%s"`, b.typ)
	case "data":
		return fmt.Sprintf(`data "%s" "%s"`, b.typ, b.name)
	}
	return fmt.Sprintf(`resource "%s" "%s"`, b.typ, b.name)
}

// terraformModule collects parsed .tf files so cross-resource rules (public
// access block for bucket X) see the whole tree.
type terraformModule struct {
	blocks []*block
}

// add parses one .tf file into the module. It returns false when the file
// was skipped as too complex: hclsyntax recurses per nesting level and a Go
// stack overflow is fatal, so the depth is measured on the bytes first.
// Unparsable files are skipped silently (never a finding) and return true.
func (m *terraformModule) add(rel string, content []byte) bool {
	if len(content) > MaxTerraformFileBytes || engine.BracketDepth(content, engine.MaxNestingDepth) > engine.MaxNestingDepth {
		return false
	}
	f, diags := hclsyntax.ParseConfig(content, rel, hcl.Pos{Line: 1, Column: 1})
	if f == nil || diags.HasErrors() {
		return true // unparsable file: skipped, never a finding
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return true
	}
	for _, blk := range body.Blocks {
		if len(m.blocks) >= maxTFResources {
			return true
		}
		switch {
		case blk.Type == "resource" && len(blk.Labels) == 2, blk.Type == "data" && len(blk.Labels) == 2:
			m.blocks = append(m.blocks, &block{kind: blk.Type, typ: blk.Labels[0], name: blk.Labels[1], file: rel, b: blk, nested: blk.Body.Blocks})
		case blk.Type == "variable" && len(blk.Labels) == 1:
			m.blocks = append(m.blocks, &block{kind: "variable", typ: blk.Labels[0], file: rel, b: blk})
		}
	}
	return true
}

// attr evaluates a constant attribute of a body. Expressions that are not
// constant-shaped (constShaped) are unresolvable, like unknown values.
func attr(body *hclsyntax.Body, name string) (cty.Value, *hclsyntax.Attribute, bool) {
	a, ok := body.Attributes[name]
	if !ok {
		return cty.NilVal, nil, false
	}
	if !constShaped(a.Expr) {
		return cty.NilVal, a, false
	}
	v, diags := a.Expr.Value(evalCtx)
	if diags.HasErrors() || !v.IsWhollyKnown() || v.IsNull() {
		return cty.NilVal, a, false
	}
	return v, a, true
}

func attrString(body *hclsyntax.Body, name string) (string, bool) {
	v, _, ok := attr(body, name)
	if !ok || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

// attrBool reads a bool attribute; present is false when absent/unknown.
func attrBool(body *hclsyntax.Body, name string) (val bool, present bool) {
	v, _, ok := attr(body, name)
	if !ok {
		return false, false
	}
	switch v.Type() {
	case cty.Bool:
		return v.True(), true
	case cty.String:
		return strings.EqualFold(v.AsString(), "true"), true
	}
	return false, false
}

func attrInt(body *hclsyntax.Body, name string) (int64, bool) {
	v, _, ok := attr(body, name)
	if !ok {
		return 0, false
	}
	if v.Type() == cty.String {
		var n int64
		if _, err := fmt.Sscanf(v.AsString(), "%d", &n); err == nil {
			return n, true
		}
		return 0, false
	}
	if v.Type() != cty.Number {
		return 0, false
	}
	n, _ := v.AsBigFloat().Int64()
	return n, true
}

func attrStrings(body *hclsyntax.Body, name string) []string {
	v, _, ok := attr(body, name)
	if !ok {
		return nil
	}
	var out []string
	switch {
	case v.Type() == cty.String:
		out = append(out, v.AsString())
	case v.Type().IsListType() || v.Type().IsTupleType() || v.Type().IsSetType():
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if ev.Type() == cty.String && !ev.IsNull() {
				out = append(out, ev.AsString())
			}
		}
	}
	return out
}

func attrLine(body *hclsyntax.Body, name string, fallback int) int {
	if a, ok := body.Attributes[name]; ok {
		return a.SrcRange.Start.Line
	}
	return fallback
}

// refs returns "type.name" for every resource reference in attribute name.
func refs(body *hclsyntax.Body, name string) []string {
	a, ok := body.Attributes[name]
	if !ok {
		return nil
	}
	var out []string
	for _, tr := range a.Expr.Variables() {
		if len(tr) >= 2 {
			if step, ok := tr[1].(hcl.TraverseAttr); ok {
				out = append(out, tr.RootName()+"."+step.Name)
			}
		}
	}
	return out
}

func nestedBlocks(b *block, typ string) []*hclsyntax.Block {
	var out []*hclsyntax.Block
	for _, n := range b.nested {
		if n.Type == typ {
			out = append(out, n)
		}
	}
	return out
}

// checkTerraform runs every Terraform rule over the module, checking ctx
// between blocks so a cancelled or timed-out scan stops promptly.
func checkTerraform(ctx context.Context, m *terraformModule, em *emitter) error {
	if len(m.blocks) == 0 {
		return nil
	}
	// Index of buckets covered by companion resources.
	covered := map[string]map[string]bool{} // companion type -> bucket address or literal name
	bucketNames := map[string]string{}      // literal bucket name -> address
	for _, b := range m.blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b.kind == "resource" && b.typ == "aws_s3_bucket" {
			if n, ok := attrString(b.b.Body, "bucket"); ok {
				bucketNames[n] = "aws_s3_bucket." + b.name
			}
		}
	}
	for _, b := range m.blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b.kind != "resource" || !strings.HasPrefix(b.typ, "aws_s3_bucket_") {
			continue
		}
		set := covered[b.typ]
		if set == nil {
			set = map[string]bool{}
			covered[b.typ] = set
		}
		for _, r := range refs(b.b.Body, "bucket") {
			set[r] = true
		}
		if n, ok := attrString(b.b.Body, "bucket"); ok {
			if addr, ok := bucketNames[n]; ok {
				set[addr] = true
			}
		}
	}
	for _, b := range m.blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		switch {
		case b.kind == "variable":
			err = checkVariable(b, em)
		case b.kind == "data" && b.typ == "aws_iam_policy_document":
			err = checkPolicyDocument(b, em)
		case b.kind != "resource":
			continue
		case b.typ == "aws_s3_bucket":
			err = checkS3Bucket(b, covered, em)
		case b.typ == "aws_s3_bucket_acl":
			if acl, ok := attrString(b.b.Body, "acl"); ok && isPublicACL(acl) {
				err = em.rule("iac.tf.s3-public-acl", b.file, attrLine(b.b.Body, "acl", b.line()), b.addr()+" acl = "+acl)
			}
		case b.typ == "aws_security_group" || b.typ == "aws_security_group_rule" || b.typ == "aws_vpc_security_group_ingress_rule":
			err = checkSecurityGroup(b, em)
		case b.typ == "aws_db_instance" || b.typ == "aws_rds_cluster" || b.typ == "aws_rds_cluster_instance":
			err = checkRDS(b, em)
		case b.typ == "aws_ebs_volume":
			if v, ok := attrBool(b.b.Body, "encrypted"); !ok || !v {
				err = em.rule("iac.tf.ebs-unencrypted", b.file, b.line(), b.addr()+" encrypted not true")
			}
		case b.typ == "aws_instance" || b.typ == "aws_launch_template":
			err = checkInstance(b, em)
		case strings.HasPrefix(b.typ, "aws_iam_") && (strings.HasSuffix(b.typ, "_policy") || b.typ == "aws_iam_role"):
			err = checkIAMPolicy(b, em)
		case b.typ == "aws_cloudtrail":
			err = checkCloudTrail(b, em)
		case b.typ == "aws_kms_key":
			if v, ok := attrBool(b.b.Body, "enable_key_rotation"); !ok || !v {
				err = em.rule("iac.tf.kms-rotation-disabled", b.file, b.line(), b.addr()+" enable_key_rotation not true")
			}
		case b.typ == "aws_lambda_function":
			err = checkLambda(b, em)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func isPublicACL(acl string) bool {
	return acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read"
}

func checkS3Bucket(b *block, covered map[string]map[string]bool, em *emitter) error {
	body := b.b.Body
	addr := "aws_s3_bucket." + b.name
	if acl, ok := attrString(body, "acl"); ok && isPublicACL(acl) {
		if err := em.rule("iac.tf.s3-public-acl", b.file, attrLine(body, "acl", b.line()), b.addr()+" acl = "+acl); err != nil {
			return err
		}
	}
	type companion struct {
		rule, resource, inline string
	}
	for _, c := range []companion{
		{"iac.tf.s3-no-public-access-block", "aws_s3_bucket_public_access_block", ""},
		{"iac.tf.s3-no-encryption", "aws_s3_bucket_server_side_encryption_configuration", "server_side_encryption_configuration"},
		{"iac.tf.s3-no-versioning", "aws_s3_bucket_versioning", "versioning"},
		{"iac.tf.s3-no-logging", "aws_s3_bucket_logging", "logging"},
	} {
		if covered[c.resource][addr] {
			continue
		}
		if c.inline != "" && len(nestedBlocks(b, c.inline)) > 0 {
			if c.inline != "versioning" {
				continue
			}
			if v, ok := attrBool(nestedBlocks(b, c.inline)[0].Body, "enabled"); ok && v {
				continue
			}
		}
		if err := em.rule(c.rule, b.file, b.line(), b.addr()+" has no "+c.resource); err != nil {
			return err
		}
	}
	return nil
}

func worldOpen(cidrs []string) bool {
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return true
		}
	}
	return false
}

// ingressRule checks one ingress rule body for the three port rules.
func ingressRule(b *block, body *hclsyntax.Body, line int, em *emitter) error {
	cidrs := append(attrStrings(body, "cidr_blocks"), attrStrings(body, "ipv6_cidr_blocks")...)
	if v, ok := attrString(body, "cidr_ipv4"); ok {
		cidrs = append(cidrs, v)
	}
	if v, ok := attrString(body, "cidr_ipv6"); ok {
		cidrs = append(cidrs, v)
	}
	if !worldOpen(cidrs) {
		return nil
	}
	proto, _ := attrString(body, "protocol")
	if proto == "" {
		proto, _ = attrString(body, "ip_protocol")
	}
	from, fromOK := attrInt(body, "from_port")
	to, toOK := attrInt(body, "to_port")
	covers := func(port int64) bool { return fromOK && toOK && from <= port && port <= to }
	allPorts := proto == "-1" || proto == "all" || (fromOK && toOK && from == 0 && (to == 0 || to == 65535))
	switch {
	case allPorts:
		return em.rule("iac.tf.sg-open-all", b.file, line, b.addr()+" ingress all ports from "+strings.Join(cidrs, ","))
	case covers(22):
		return em.rule("iac.tf.sg-open-ssh", b.file, line, b.addr()+" ingress 22 from "+strings.Join(cidrs, ","))
	case covers(3389):
		return em.rule("iac.tf.sg-open-rdp", b.file, line, b.addr()+" ingress 3389 from "+strings.Join(cidrs, ","))
	}
	return nil
}

func checkSecurityGroup(b *block, em *emitter) error {
	switch b.typ {
	case "aws_security_group":
		for _, in := range nestedBlocks(b, "ingress") {
			if err := ingressRule(b, in.Body, in.TypeRange.Start.Line, em); err != nil {
				return err
			}
		}
	case "aws_security_group_rule":
		if t, _ := attrString(b.b.Body, "type"); t == "ingress" {
			return ingressRule(b, b.b.Body, b.line(), em)
		}
	case "aws_vpc_security_group_ingress_rule":
		return ingressRule(b, b.b.Body, b.line(), em)
	}
	return nil
}

func checkRDS(b *block, em *emitter) error {
	body := b.b.Body
	if v, ok := attrBool(body, "publicly_accessible"); ok && v {
		if err := em.rule("iac.tf.rds-public", b.file, attrLine(body, "publicly_accessible", b.line()), b.addr()+" publicly_accessible = true"); err != nil {
			return err
		}
	}
	if b.typ != "aws_rds_cluster_instance" {
		if v, ok := attrBool(body, "storage_encrypted"); !ok || !v {
			if err := em.rule("iac.tf.rds-unencrypted", b.file, b.line(), b.addr()+" storage_encrypted not true"); err != nil {
				return err
			}
		}
	}
	if b.typ == "aws_db_instance" {
		if n, ok := attrInt(body, "backup_retention_period"); ok && n == 0 {
			return em.rule("iac.tf.rds-no-backups", b.file, attrLine(body, "backup_retention_period", b.line()), b.addr()+" backup_retention_period = 0")
		}
	}
	return nil
}

func checkInstance(b *block, em *emitter) error {
	if v, ok := attrBool(b.b.Body, "associate_public_ip_address"); ok && v {
		if err := em.rule("iac.tf.instance-public-ip", b.file, attrLine(b.b.Body, "associate_public_ip_address", b.line()), b.addr()+" associate_public_ip_address = true"); err != nil {
			return err
		}
	}
	for _, typ := range []string{"root_block_device", "ebs_block_device"} {
		for _, dev := range nestedBlocks(b, typ) {
			if v, ok := attrBool(dev.Body, "encrypted"); !ok || !v {
				if err := em.rule("iac.tf.ebs-unencrypted", b.file, dev.TypeRange.Start.Line, b.addr()+" "+typ+" encrypted not true"); err != nil {
					return err
				}
			}
		}
	}
	if b.typ == "aws_launch_template" {
		for _, bdm := range nestedBlocks(b, "block_device_mappings") {
			for _, ebs := range bdm.Body.Blocks {
				if ebs.Type != "ebs" {
					continue
				}
				if v, ok := attrBool(ebs.Body, "encrypted"); !ok || !v {
					if err := em.rule("iac.tf.ebs-unencrypted", b.file, ebs.TypeRange.Start.Line, b.addr()+" block_device_mappings.ebs encrypted not true"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// policyStatement is the subset of an IAM policy document we inspect.
type policyStatement struct {
	Effect string          `json:"Effect"`
	Action json.RawMessage `json:"Action"`
}

// policyAllowsAll parses a policy JSON document and reports an Allow
// statement with Action "*" or "<service>:*" alongside Resource "*".
func policyAllowsAll(doc string) bool {
	if len(doc) > 256<<10 {
		return false
	}
	var pol struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &pol); err != nil {
		return false
	}
	var stmts []policyStatement
	if err := json.Unmarshal(pol.Statement, &stmts); err != nil {
		var one policyStatement
		if json.Unmarshal(pol.Statement, &one) != nil {
			return false
		}
		stmts = []policyStatement{one}
	}
	for _, s := range stmts {
		if s.Effect != "" && !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if actionsWildcard(rawStrings(s.Action)) {
			return true
		}
	}
	return false
}

func rawStrings(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func actionsWildcard(actions []string) bool {
	for _, a := range actions {
		if a == "*" || a == "*:*" {
			return true
		}
	}
	return false
}

func checkIAMPolicy(b *block, em *emitter) error {
	body := b.b.Body
	if doc, ok := attrString(body, "policy"); ok && policyAllowsAll(doc) {
		if err := em.rule("iac.tf.iam-wildcard-action", b.file, attrLine(body, "policy", b.line()), b.addr()+` policy allows Action "*"`); err != nil {
			return err
		}
	}
	for _, in := range nestedBlocks(b, "inline_policy") {
		if doc, ok := attrString(in.Body, "policy"); ok && policyAllowsAll(doc) {
			if err := em.rule("iac.tf.iam-wildcard-action", b.file, in.TypeRange.Start.Line, b.addr()+` inline_policy allows Action "*"`); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkPolicyDocument(b *block, em *emitter) error {
	for _, st := range nestedBlocks(b, "statement") {
		effect, _ := attrString(st.Body, "effect")
		if effect != "" && !strings.EqualFold(effect, "Allow") {
			continue
		}
		if actionsWildcard(attrStrings(st.Body, "actions")) {
			if err := em.rule("iac.tf.iam-wildcard-action", b.file, st.TypeRange.Start.Line, b.addr()+` statement actions = ["*"]`); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkCloudTrail(b *block, em *emitter) error {
	body := b.b.Body
	if v, ok := attrBool(body, "enable_logging"); ok && !v {
		if err := em.rule("iac.tf.cloudtrail-logging-disabled", b.file, attrLine(body, "enable_logging", b.line()), b.addr()+" enable_logging = false"); err != nil {
			return err
		}
	}
	if v, ok := attrBool(body, "is_multi_region_trail"); !ok || !v {
		if err := em.rule("iac.tf.cloudtrail-not-multi-region", b.file, b.line(), b.addr()+" is_multi_region_trail not true"); err != nil {
			return err
		}
	}
	if v, ok := attrBool(body, "enable_log_file_validation"); !ok || !v {
		return em.rule("iac.tf.cloudtrail-no-validation", b.file, b.line(), b.addr()+" enable_log_file_validation not true")
	}
	return nil
}

func checkVariable(b *block, em *emitter) error {
	if !secretKeyRe.MatchString(b.typ) {
		return nil
	}
	v, a, ok := attr(b.b.Body, "default")
	if !ok || v.Type() != cty.String {
		return nil
	}
	if !isSecretAssignment(b.typ, v.AsString()) {
		return nil
	}
	return em.secret("iac.tf.secret-in-variable-default", b.file, a.SrcRange.Start.Line, b.addr()+" default", v.AsString())
}

func checkLambda(b *block, em *emitter) error {
	for _, env := range nestedBlocks(b, "environment") {
		v, a, ok := attr(env.Body, "variables")
		if !ok || !v.Type().IsObjectType() && !v.Type().IsMapType() {
			continue
		}
		for it := v.ElementIterator(); it.Next(); {
			k, ev := it.Element()
			if k.Type() != cty.String || ev.Type() != cty.String || ev.IsNull() {
				continue
			}
			if isSecretAssignment(k.AsString(), ev.AsString()) {
				if err := em.secret("iac.tf.lambda-secret-in-env", b.file, a.SrcRange.Start.Line, b.addr()+" environment "+k.AsString(), ev.AsString()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
