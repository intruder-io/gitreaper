package scan

import (
	_ "embed"
	"encoding/json"
	"os"
	"regexp"
)

//go:embed rules.json
var defaultRulesJSON []byte

// RuleType classifies how a rule detects secrets.
type RuleType int8

const (
	// RuleTypeToken matches a self-identifying token with a vendor-specific prefix.
	// No false-positive reduction is applied — the prefix is sufficient evidence.
	RuleTypeToken RuleType = iota
	// RuleTypeContext matches a key=value assignment where the key implies a secret type.
	// The value is extracted and checked against Validate to suppress false positives.
	RuleTypeContext
	// RuleTypePath matches against the file path rather than file content.
	RuleTypePath
)

// Validate specifies the false-positive checks applied to the extracted value
// of a context rule. Zero values disable the corresponding check.
type Validate struct {
	URLCred           bool    // extract and validate URL credentials (user:pass@host) instead of generic value
	EntropyMin        float64 // minimum Shannon entropy of the extracted value; 0 = disabled
	NotPlaceholder    bool    // reject known placeholder words (e.g. "changeme", "yourpassword")
	NotRuntimeValue   bool    // reject lines that fetch the value at runtime (getenv, os.environ, etc.)
	NotTemplateVar    bool    // reject template/interpolation syntax (${VAR}, {{var}}, etc.) in the value
	NotAllSameChar    bool    // reject values composed of a single repeated character
	NotFunctionValue  bool    // reject extracted values that appear to be function/method call expressions (contain "(")
	NotBareIdentifier  bool    // reject extracted values that are pure identifiers (letters/digits/underscores only — constant or variable references, not string literals)
	NotPropertyAccess bool    // reject extracted values that look like dotted property chains (a.xa, this.token, obj.prop.sub) — runtime object references, not literals
}

// Rule is a compiled secret-detection rule ready for scanning.
type Rule struct {
	Name         string
	Desc         string
	Group        string
	Severity     string
	Tags         []string
	Type         RuleType
	GroupEnabled bool // false when the source group has enabled:false (opt-in group)

	Pattern   *regexp.Regexp // token/path: full match pattern; context: detection pattern
	Extract   *regexp.Regexp // context: captures value via group 1 for FP checks; nil → default extractor
	SkipPaths *regexp.Regexp // content rules: skip this rule when the file path matches; nil = apply to all paths
	Validate  Validate       // context rules only
}

// ── JSON source structures ─────────────────────────────────────────────────────

type validateDef struct {
	ExtractMode      string  `json:"extract_mode,omitempty"` // "" | "url_cred"
	EntropyMin       float64 `json:"entropy_min,omitempty"`
	NotPlaceholder   bool    `json:"not_placeholder,omitempty"`
	NotRuntimeValue  bool    `json:"not_runtime_value,omitempty"`
	NotTemplateVar   bool    `json:"not_template_var,omitempty"`
	NotAllSameChar   bool    `json:"not_all_same_char,omitempty"`
	NotFunctionValue  bool    `json:"not_function_value,omitempty"`
	NotBareIdentifier  bool    `json:"not_bare_identifier,omitempty"`
	NotPropertyAccess bool    `json:"not_property_access,omitempty"`
}

type ruleDef struct {
	Type      string      `json:"type"`               // "token" | "context" | "path"
	Name      string      `json:"name"`
	Desc      string      `json:"desc"`
	Severity  string      `json:"severity,omitempty"` // overrides group severity for this rule
	Pattern   string      `json:"pattern"`
	Extract   string      `json:"extract,omitempty"`   // context: regex with group 1 = extracted value
	SkipPaths string      `json:"skip_paths,omitempty"` // content rules: skip when file path matches
	Validate  validateDef `json:"validate,omitempty"`
}

type groupDef struct {
	Group    string    `json:"group"`
	Severity string    `json:"severity,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Enabled  *bool     `json:"enabled,omitempty"` // nil → true (enabled by default)
	Rules    []ruleDef `json:"rules"`
}

// ── Public API ─────────────────────────────────────────────────────────────────

// DefaultRules returns all compiled rules from the embedded rules.json,
// including groups with enabled:false.
// Call ActiveRules to apply group filtering.
// Panics if the embedded file is malformed (programmer error).
func DefaultRules() []Rule {
	rules, err := compileGroups(defaultRulesJSON)
	if err != nil {
		panic("built-in rules.json failed to parse: " + err.Error())
	}
	return rules
}

// LoadRulesFile reads and compiles rules from a JSON file on disk.
func LoadRulesFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return compileGroups(data)
}

// ActiveRules filters a rule set by enabled status and group selectors.
//
//   - Rules in disable are always excluded.
//   - Rules in enable are always included (even if GroupEnabled=false).
//   - All other rules are included only if GroupEnabled=true.
func ActiveRules(rules []Rule, enable, disable []string) []Rule {
	en := toSet(enable)
	dis := toSet(disable)
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if dis[r.Group] {
			continue
		}
		if en[r.Group] || r.GroupEnabled {
			out = append(out, r)
		}
	}
	return out
}

// GroupInfo summarises a rule group for display.
type GroupInfo struct {
	Name     string
	Severity string
	Tags     []string
	Enabled  bool
	Count    int
}

// ListGroups returns one GroupInfo per group present in rules, in source order.
func ListGroups(rules []Rule) []GroupInfo {
	order := make([]string, 0)
	index := make(map[string]int)
	var out []GroupInfo
	for _, r := range rules {
		if i, ok := index[r.Group]; ok {
			out[i].Count++
			continue
		}
		index[r.Group] = len(out)
		order = append(order, r.Group)
		out = append(out, GroupInfo{
			Name:     r.Group,
			Severity: r.Severity,
			Tags:     r.Tags,
			Enabled:  r.GroupEnabled,
			Count:    1,
		})
	}
	_ = order
	return out
}

// ── Compilation ────────────────────────────────────────────────────────────────

func compileGroups(data []byte) ([]Rule, error) {
	var groups []groupDef
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, err
	}
	var rules []Rule
	for _, g := range groups {
		enabled := g.Enabled == nil || *g.Enabled
		for _, d := range g.Rules {
			r, err := compileRule(d, g, enabled)
			if err != nil {
				continue // skip rules whose patterns fail to compile
			}
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func compileRule(d ruleDef, g groupDef, groupEnabled bool) (Rule, error) {
	pat, err := regexp.Compile(d.Pattern)
	if err != nil {
		return Rule{}, err
	}

	var ruleType RuleType
	switch d.Type {
	case "context":
		ruleType = RuleTypeContext
	case "path":
		ruleType = RuleTypePath
	default:
		ruleType = RuleTypeToken
	}

	var extract *regexp.Regexp
	if d.Extract != "" {
		if extract, err = regexp.Compile(d.Extract); err != nil {
			return Rule{}, err
		}
	}

	var skipPaths *regexp.Regexp
	if d.SkipPaths != "" {
		if skipPaths, err = regexp.Compile(d.SkipPaths); err != nil {
			return Rule{}, err
		}
	}

	severity := d.Severity
	if severity == "" {
		severity = g.Severity
	}

	v := d.Validate
	validate := Validate{
		URLCred:          v.ExtractMode == "url_cred",
		EntropyMin:       v.EntropyMin,
		NotPlaceholder:   v.NotPlaceholder,
		NotRuntimeValue:  v.NotRuntimeValue,
		NotTemplateVar:   v.NotTemplateVar,
		NotAllSameChar:   v.NotAllSameChar,
		NotFunctionValue:  v.NotFunctionValue,
		NotBareIdentifier:  v.NotBareIdentifier,
		NotPropertyAccess: v.NotPropertyAccess,
	}

	return Rule{
		Name:         d.Name,
		Desc:         d.Desc,
		Group:        g.Group,
		Severity:     severity,
		Tags:         g.Tags,
		Type:         ruleType,
		GroupEnabled: groupEnabled,
		Pattern:      pat,
		Extract:      extract,
		SkipPaths:    skipPaths,
		Validate:     validate,
	}, nil
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, s := range items {
		if s != "" {
			m[s] = true
		}
	}
	return m
}
