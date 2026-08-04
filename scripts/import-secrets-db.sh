#!/usr/bin/env bash
# import-secrets-db.sh — download and convert secrets-patterns-db to gitreaper JSON rules
#
# Usage:
#   ./scripts/import-secrets-db.sh [OPTIONS]
#
# Options:
#   -o FILE       Output file (default: rules-community.json)
#   -c LEVEL      Minimum confidence level: high|low|all (default: high)
#   -p PREFIX     Name prefix for imported rules (default: ext-)
#   -f FILE       Use a local YAML file instead of downloading
#   --no-dedup    Skip deduplication against built-in rules.json
#   -h            Show this help
#
# Requires: python3 (with PyYAML), curl or wget
# PyYAML install: pip3 install pyyaml
#
# Source: https://github.com/mazen160/secrets-patterns-db

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
OUTPUT="rules-community.json"
CONFIDENCE="high"
PREFIX="ext-"
LOCAL_FILE=""
NO_DEDUP=false
BUILTIN_RULES="$(dirname "$0")/../internal/scan/rules.json"
YAML_URL="https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml"

# ── Arg parsing ───────────────────────────────────────────────────────────────
usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,2\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUTPUT="$2"; shift 2 ;;
    -c) CONFIDENCE="$2"; shift 2 ;;
    -p) PREFIX="$2"; shift 2 ;;
    -f) LOCAL_FILE="$2"; shift 2 ;;
    --no-dedup) NO_DEDUP=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Preflight checks ──────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is required. Install it with: brew install python3" >&2
  exit 1
fi

# Locate a python3 that has PyYAML available. Honour PYTHON3 env var override.
if [[ -n "${PYTHON3:-}" ]]; then
  PY="$PYTHON3"
elif python3 -c "import yaml" 2>/dev/null; then
  PY="python3"
else
  echo "ERROR: PyYAML is not available to the system python3." >&2
  echo "  Options:" >&2
  echo "    pip3 install pyyaml" >&2
  echo "    brew install python3 (reinstall with PyYAML)" >&2
  echo "    python3 -m venv /tmp/gr-venv && /tmp/gr-venv/bin/pip install pyyaml" >&2
  echo "    Then: PYTHON3=/tmp/gr-venv/bin/python3 $0 $*" >&2
  exit 1
fi

# ── Download YAML if no local file ────────────────────────────────────────────
YAML_FILE="$LOCAL_FILE"
if [[ -z "$YAML_FILE" ]]; then
  YAML_FILE="$(mktemp /tmp/secrets-patterns-db-XXXXXX.yml)"
  trap 'rm -f "$YAML_FILE"' EXIT

  echo "Downloading secrets-patterns-db..." >&2
  if command -v curl &>/dev/null; then
    curl -fsSL "$YAML_URL" -o "$YAML_FILE"
  elif command -v wget &>/dev/null; then
    wget -q "$YAML_URL" -O "$YAML_FILE"
  else
    echo "ERROR: curl or wget is required to download the database." >&2
    exit 1
  fi
  echo "Downloaded $(wc -l < "$YAML_FILE") lines." >&2
fi

# ── Extract existing rule names from built-in rules (for dedup) ───────────────
# rules.json is a list of groups, each with a nested "rules" array — not a flat
# list of rules — so dedup has to walk into each group.
EXISTING_NAMES=""
if [[ "$NO_DEDUP" == false && -f "$BUILTIN_RULES" ]]; then
  EXISTING_NAMES=$("$PY" -c "
import json, sys
with open('$BUILTIN_RULES') as f:
    groups = json.load(f)
for g in groups:
    for r in g['rules']:
        print(r['name'])
" 2>/dev/null || true)
fi

# ── Convert YAML → gitreaper JSON with embedded Python ───────────────────────
echo "Converting rules (confidence=${CONFIDENCE}, prefix='${PREFIX}')..." >&2

"$PY" - <<PYEOF
import yaml, json, re, sys

CONFIDENCE_FILTER = "${CONFIDENCE}"
PREFIX            = "${PREFIX}"
EXISTING_NAMES    = set("""${EXISTING_NAMES}""".split()) if """${EXISTING_NAMES}""" else set()

def slugify(name):
    """Convert 'AWS API Key' → 'aws-api-key'"""
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s

def is_re2_compatible(pattern):
    """
    Quick check for RE2-incompatible constructs.
    Go's regexp package (RE2) does not support:
      - lookaheads / lookbehinds: (?=...) (?!...) (?<=...) (?<!...)
      - possessive quantifiers:   *+ ++ ?+ {n,m}+
      - atomic groups:            (?>...)
      - backreferences:           \\1 \\2 etc. (other than named captures in some modes)
      - conditional groups:       (?(cond)yes|no)
    """
    bad = [
        r'\(\?[=!]',          # lookahead (?=...) (?!...)
        r'\(\?<[=!]',         # lookbehind (?<=...) (?<!...)
        r'\(\?>',             # atomic group (?>...)
        r'(?<![?])\*\+',      # possessive *+
        r'(?<![?])\+\+',      # possessive ++
        r'(?<![?])\?\+',      # possessive ?+
        r'\(\?\(',            # conditional group
        r'\\[0-9]',           # backreference
    ]
    for b in bad:
        if re.search(b, pattern):
            return False, b
    # Also try compiling in Python as a sanity check
    try:
        re.compile(pattern)
    except re.error as e:
        return False, str(e)
    return True, None

# Load YAML
with open("${YAML_FILE}") as f:
    data = yaml.safe_load(f)

patterns = data.get("patterns", [])

results = []
skipped_compat = 0
skipped_conf   = 0
skipped_dedup  = 0
seen_slugs     = set()

for entry in patterns:
    p = entry.get("pattern", {})
    name       = p.get("name", "").strip()
    regex      = p.get("regex", "").strip()
    confidence = p.get("confidence", "low").strip().lower()

    if not name or not regex:
        continue

    # Confidence filter
    if CONFIDENCE_FILTER == "high" and confidence != "high":
        skipped_conf += 1
        continue
    # "low" means include both high and low; "all" is the same

    # RE2 compatibility check
    ok, reason = is_re2_compatible(regex)
    if not ok:
        print(f"  SKIP (RE2 incompatible, {reason}): {name}", file=sys.stderr)
        skipped_compat += 1
        continue

    slug = PREFIX + slugify(name)

    # Dedup: skip if slug already exists in built-in rules
    if slug in EXISTING_NAMES or slug in seen_slugs:
        skipped_dedup += 1
        continue
    seen_slugs.add(slug)

    # High-confidence patterns are vendor-specific enough that the match itself
    # is sufficient evidence — "token" rule, no FP filtering.
    # Low-confidence patterns are broader (often just "key_name(=|:)" with no
    # value captured) and benefit from the generic context-rule FP checks,
    # applied to whatever defaultExtractRE pulls from after the "=" or ":".
    if confidence == "high":
        rule = {"type": "token", "name": slug, "desc": name, "pattern": regex}
    else:
        rule = {
            "type": "context",
            "name": slug,
            "desc": name,
            "pattern": regex,
            "validate": {
                "entropy_min": 3.0,
                "not_placeholder": True,
                "not_runtime_value": True,
                "not_template_var": True,
                "not_all_same_char": True,
            },
        }
    results.append(rule)

# Write output — wrap the flat rule list in the group schema rules.json/rules.go
# expect: a JSON array of {group, severity, tags, rules: [...]}.
output_path = "${OUTPUT}"
group = {
    "group": PREFIX.rstrip("-") + "-imported",
    "severity": "medium",
    "tags": ["community", "imported"],
    "rules": results,
}
with open(output_path, "w") as f:
    json.dump([group], f, indent=2)
    f.write("\n")

print(f"Wrote {len(results)} rules to {output_path}", file=sys.stderr)
print(f"  Skipped {skipped_conf} (confidence filter)", file=sys.stderr)
print(f"  Skipped {skipped_compat} (RE2 incompatible)", file=sys.stderr)
print(f"  Skipped {skipped_dedup} (duplicate name)", file=sys.stderr)
PYEOF

echo ""
echo "Done. Use with gitreaper:"
echo "  gitreaper -rules ${OUTPUT} ..."
echo "  gitreaper -rules ${OUTPUT} -no-default-rules ...  # community rules only"
