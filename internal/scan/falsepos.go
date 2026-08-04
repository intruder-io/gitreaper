package scan

import (
	"math"
	"regexp"
	"strings"
)

// isFalsePositive returns true if the matched line is likely not a real secret.
//
// For url_cred rules, it extracts user:pass from the URL and checks them directly.
// For all other context rules:
//   - NotRuntimeValue is checked against the full line (env lookups can appear anywhere)
//   - All other checks are applied to the extracted value only — never the full line.
//     Applying template-var checks to the full line would suppress real secrets in
//     assignments like  $password = 'actualSecret'  where the LHS looks like a template.
func isFalsePositive(line, value string, v Validate) bool {
	if v.URLCred {
		return isPlaceholderURLCred(line)
	}
	if v.NotRuntimeValue && runtimeValueRE.MatchString(line) {
		return true
	}
	if value == "" {
		return false
	}
	val := strings.ToLower(strings.Trim(value, "'\"`"))
	if v.NotTemplateVar && templateVarRE.MatchString(val) {
		return true
	}
	if v.NotPlaceholder && (placeholderPasswords[val] || placeholderAPIKeys[val] || valuePlaceholderRE.MatchString(val)) {
		return true
	}
	if v.NotAllSameChar && isAllSameChar(val) {
		return true
	}
	if v.NotFunctionValue && strings.Contains(val, "(") {
		return true
	}
	if v.NotBareIdentifier && bareIdentRE.MatchString(val) {
		return true
	}
	if v.NotPropertyAccess && propertyAccessRE.MatchString(val) {
		return true
	}
	if v.EntropyMin > 0 && len(val) >= 8 && shannonEntropy(val) < v.EntropyMin {
		return true
	}
	return false
}

// ── Compiled regexes ──────────────────────────────────────────────────────────

// defaultExtractRE extracts the value from a generic key=value or key: value assignment.
// Used by context rules that do not specify an explicit extract pattern.
var defaultExtractRE = regexp.MustCompile(`(?i)[=:]\s*['` + "`" + `"]?([^\s'` + "`" + `",;:)]{4,256})['` + "`" + `"]?`)

// runtimeValueRE detects lines where the secret value is supplied at runtime rather than
// being a hardcoded literal. Safe to apply to the FULL LINE — none of these constructs
// can appear inside an actual hardcoded secret value.
var runtimeValueRE = regexp.MustCompile(
	`['"]\s*\.\s*\$[a-zA-Z_]\w*` + // PHP concat: 'literal' . $var
		`|(?i)\bgetenv\s*\(` + // getenv("KEY")
		`|(?i)\benv\s*\(\s*['"]` + // env("KEY") — require quote to avoid matching "environ"
		`|(?i)\bconfig\s*\(\s*['"]` + // config("key") — Laravel helper
		`|\$_ENV\s*\[` + // $_ENV["KEY"]
		`|\$_SERVER\s*\[` + // $_SERVER["KEY"]
		`|process\.env\.` + // process.env.KEY
		`|os\.environ\b` + // os.environ[...] / os.environ.get(
		`|os\.getenv\s*\(` + // os.getenv("KEY")
		`|\bENV\s*\[` + // ENV["KEY"] — Ruby
		`|System\.getenv\s*\(` + // System.getenv("KEY") — Java
		// Web framework request/input accessors
		`|(?i)\brequest\.(form|args|get|post|json|data|values|params|body|cookies|headers)\b` + // Flask/Django/Express request.*
		`|(?i)\brequest\.(getParameter|getHeader|getAttribute)\s*\(` + // Java Servlet
		`|(?i)\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[` + // PHP superglobals
		`|(?i)\bparams\s*[\[.]` + // Rails params[...] / params.key
		`|(?i)\binput\s*\(\s*['"]` + // Laravel input("key")
		`|(?i)\breq\.(body|query|params)\b`, // Express req.body / req.query / req.params
)

// templateVarRE detects common template/interpolation placeholder syntaxes.
// Applied only to extracted values, NOT to full lines.
var templateVarRE = regexp.MustCompile(
	`\$\{[^}]{1,80}\}` + // ${VAR_NAME}
		`|\$[a-zA-Z_]\w{0,63}` + // $variable / $VARIABLE
		`|%[a-zA-Z_]\w{0,63}%` + // %variable%
		`|\{\{[^}]{1,80}\}\}` + // {{variable}}
		`|<[a-zA-Z_][a-zA-Z0-9_\-]{0,62}>` + // <var-name>
		`|\[[a-zA-Z_][a-zA-Z0-9_\-]{0,62}\]` + // [VAR_NAME]
		`|__[A-Z][A-Z0-9_]{1,62}__`, // __VAR_NAME__
)

// urlCredRE extracts (username, password) from a URL with embedded credentials.
var urlCredRE = regexp.MustCompile(`://([^:@/\s]{1,256}):([^:@/\s]{1,512})@`)

// bareIdentRE matches values that follow common code identifier naming conventions.
// Only values that look like variable/constant references are suppressed; values
// containing digits or inconsistent casing (e.g. BoUt3U4zPA85avj, my_P4ss_w0rd)
// do not match and are left for the entropy check to decide.
var bareIdentRE = regexp.MustCompile(
	`^[a-z][a-z]*(_[a-z]+)+$` + // snake_case: db_pass, my_api_key
		`|^[A-Z][A-Z]*(_[A-Z]+)*$` + // UPPER_CASE: SECRET, DB_PASS
		`|^[a-z][a-z]*([A-Z][a-z]+)+$` + // camelCase: dbPass, myApiKey
		`|^([A-Z][a-z]+){2,}$` + // PascalCase: DbPass, SmtpPassword
		`|^[a-z]{4,}$`, // plain lowercase word: something, mypassword
)

// propertyAccessRE matches dotted property-access chains (e.g. a.xa, this.token,
// that.options.store_token) — runtime object references, not string literals.
var propertyAccessRE = regexp.MustCompile(`^[a-zA-Z_$][\w$]*(\.[a-zA-Z_$][\w$]*)+$`)

// valuePlaceholderRE matches values that are themselves explicit placeholder phrases.
var valuePlaceholderRE = regexp.MustCompile(
	`(?i)^(` +
		`your[-_]?api[-_]?key|your[-_]?secret|your[-_]?token|your[-_]?password|` +
		`change[-_]?me|change[-_]?this|replace[-_]?me|replace[-_]?this|` +
		`insert[-_]?here|goes[-_]?here|put[-_]?here|` +
		`add[-_]?your|enter[-_]?your|fill[-_]?in|` +
		`api[-_]?key[-_]?here|token[-_]?here|secret[-_]?here` +
		`)$`,
)

// ── Placeholder sets ──────────────────────────────────────────────────────────

var placeholderUsers = strSet(
	"user", "username", "uname", "login", "name",
	"admin", "administrator", "root", "guest", "anonymous", "anon", "nobody",
	"test", "testuser", "demo", "demouser", "example", "sample",
	"myuser", "newuser", "dbuser", "db_user", "appuser", "app_user",
	"scott",                      // classic Oracle/JDBC example user
	"your_user", "your_username", // doc placeholders
	"foo", "bar", "baz",
	"john", "jane", "alice", "bob",
	"someone", "somebody", "owner",
	"user1", "user2", "testadmin",
)

var placeholderPasswords = strSet(
	"password", "passwd", "pass", "pwd", "secret",
	"mysecret", "yoursecret", "yourpassword", "your_password", "mypassword", "my_password",
	"changeme", "change_me", "changethis",
	"replace", "replaceme", "replace_me",
	"placeholder", "dummy", "required",
	"admin", "root", "guest", "toor",
	"test", "testing", "testpass",
	"example", "sample", "demo",
	"bad-password", "badpassword", "bad_password", "wrong",
	"qwerty", "letmein", "iloveyou", "monkey", "dragon",
	"password1", "password123", "p4ssw0rd", "passw0rd",
	"topsecret", "top_secret", "supersecret",
	"abc123", "abc",
	"hunter2",
	"nopassword", "nopass", "empty", "none", "null", "nil", "undefined", "n/a",
	"123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
	"111111", "222222", "000000", "aaaaaa", "xxxxxx", "zzzzzz",
)

var placeholderAPIKeys = strSet(
	"your_api_key", "yourapikey", "api_key_here", "apikey", "YOUR_API_KEY_HERE",
	"your_token", "yourtoken", "token_here",
	"your_secret", "yoursecret", "secret_here",
	"abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnop",
	"0000000000000000", "1111111111111111",
	"xxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxx",
)

// ── Rule-specific checks ──────────────────────────────────────────────────────

// isPlaceholderURLCred checks whether the credentials embedded in a URL are placeholders.
func isPlaceholderURLCred(line string) bool {
	m := urlCredRE.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	user := strings.ToLower(m[1])
	pass := strings.ToLower(m[2])
	if templateVarRE.MatchString(user) || templateVarRE.MatchString(pass) {
		return true
	}
	if placeholderUsers[user] || placeholderPasswords[pass] {
		return true
	}
	if valuePlaceholderRE.MatchString(user) || valuePlaceholderRE.MatchString(pass) {
		return true
	}
	if isAllSameChar(user) || isAllSameChar(pass) {
		return true
	}
	return false
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isAllSameChar(s string) bool {
	if len(s) < 3 {
		return false
	}
	runes := []rune(strings.ToLower(s))
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	var n float64
	for _, r := range s {
		freq[r]++
		n++
	}
	var h float64
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	return h
}

func strSet(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}
