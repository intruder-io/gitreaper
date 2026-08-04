package scan

import (
	"bufio"
	"bytes"
	"strings"
)

// Finding is a discovered secret within a repository.
type Finding struct {
	RepoURL     string   `json:"repo_url"`
	CommitHash  string   `json:"commit_hash"`
	FilePath    string   `json:"file_path"`
	LineNum     int      `json:"line_num"`
	Line        string   `json:"line"`
	RuleName    string   `json:"rule_name"`
	RuleDesc    string   `json:"rule_desc"`
	Severity    string   `json:"severity"`
	Group       string   `json:"group"`
	Tags        []string `json:"tags,omitempty"`
	FileContent string   `json:"file_content,omitempty"`
}

// Match is an individual regex hit within a single file.
type Match struct {
	Line     int
	Text     string
	RuleName string
	RuleDesc string
	Severity string
	Group    string
	Tags     []string
}

// ScanContent scans the raw bytes of a file for secret patterns.
// path is the repo-relative file path, used to apply per-rule SkipPaths filters.
// Each line is tested against all content rules; at most one match per line is reported.
// Path rules are skipped — use ScanPath for those.
// If noFPReduction is true, Validate checks on context rules are skipped entirely.
func ScanContent(rules []Rule, content []byte, noFPReduction bool, path string) []Match {
	var matches []Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// Skip lines that are implausibly long — minified JS/CSS crams entire
		// files onto 1–3 lines of thousands of characters. Real source code
		// rarely exceeds 500 chars per line, and no legitimate secret assignment
		// appears on a line this long. Skipping avoids a large class of FPs from
		// bundled third-party libraries (firebase-core.js, vendor bundles, etc.).
		if len(line) > 500 {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, rule := range rules {
			if rule.Type == RuleTypePath {
				continue
			}
			if rule.SkipPaths != nil && rule.SkipPaths.MatchString(path) {
				continue
			}
			if !rule.Pattern.MatchString(line) {
				continue
			}
			if rule.Type == RuleTypeContext && !noFPReduction {
				value := extractValue(line, rule)
				if isFalsePositive(line, value, rule.Validate) {
					continue
				}
			}
			matches = append(matches, Match{
				Line:     lineNum,
				Text:     trimmed,
				RuleName: rule.Name,
				RuleDesc: rule.Desc,
				Severity: rule.Severity,
				Group:    rule.Group,
				Tags:     rule.Tags,
			})
			break // one match per line
		}
	}
	return matches
}

// ScanPath checks the file path against all path rules.
// Returns one Match per matching rule, with Line=0.
func ScanPath(rules []Rule, path string) []Match {
	var matches []Match
	for _, rule := range rules {
		if rule.Type != RuleTypePath {
			continue
		}
		if rule.Pattern.MatchString(path) {
			matches = append(matches, Match{
				Line:     0,
				Text:     path,
				RuleName: rule.Name,
				RuleDesc: rule.Desc,
				Severity: rule.Severity,
				Group:    rule.Group,
				Tags:     rule.Tags,
			})
		}
	}
	return matches
}

// extractValue pulls the secret value from a line for FP validation.
// Uses rule.Extract (group 1) if set; otherwise falls back to defaultExtractRE.
// Returns "" when url_cred mode is active (isFalsePositive handles extraction itself).
func extractValue(line string, rule Rule) string {
	if rule.Validate.URLCred {
		return "" // URL credential extraction is handled inside isFalsePositive
	}
	if rule.Extract != nil {
		if m := rule.Extract.FindStringSubmatch(line); len(m) > 1 {
			return m[1]
		}
		return ""
	}
	if m := defaultExtractRE.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	return ""
}
