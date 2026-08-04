# [gitreaper](https://www.intruder.io/research/api-keys-bank-details-disciplinary-files-what-28-000-exposed-git-repos-gave-up) by [Intruder](https://intruder.io)

> **Research-grade tool.** Built quickly for internal research, not intended for production use or wide distribution. Treat it as a prototype, not a supported tool.

Scan exposed `.git` directories for secrets. Reconstructs repository history from a live HTTP target, scans every blob against a rule set, and reports findings with commit hash, file path, and line number.

## Features

- Reconstructs git history via loose objects and pack files — no directory listing required
- Falls back to `.git/index` parsing when the object graph is inaccessible (e.g. objects served individually but pack files blocked)
- WAF bypass: sends a Chrome `User-Agent` header to avoid ModSecurity and similar filters
- 1000+ built-in rules covering private keys, cloud credentials, API tokens, framework secrets, and generic patterns, plus imports from [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) — all in one grouped `internal/scan/rules.json`
- `scripts/import-secrets-db.sh` to pull in fresh community patterns as a separate `-rules` file
- Data-driven false-positive reduction: placeholder detection, runtime-value detection, and Shannon entropy filtering
- Concurrent scanning across many targets with a live progress bar
- NDJSON output and per-target file output for pipeline integration
- Optional repo dump: write the HEAD working tree to disk

## Install

```bash
go install github.com/intruder-io/gitreaper@latest
```

Or build from source:

```bash
git clone https://github.com/intruder-io/gitreaper
cd gitreaper
go build -o gitreaper .
```

Requires Go 1.21+. No external dependencies.

## Usage

```bash
# Single target
gitreaper https://example.com/.git

# Multiple targets
gitreaper https://example.com/.git https://other.com/.git

# From a file (one URL per line, # comments supported)
gitreaper -urls targets.txt

# From stdin
cat targets.txt | gitreaper

# URL normalisation — these are all equivalent
gitreaper https://example.com
gitreaper https://example.com/.git
gitreaper https://example.com/app.git
```

## Output

Default text output, one finding per match:

```
[https://example.com/.git] commit:89fc077a path:.env rule:generic-secret
  line 14: JWT_SECRET=s3cr3tV4lue!

[https://example.com/.git] commit:89fc077a path:.env rule:aws-access-key-id
  line 3: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

NDJSON (one JSON object per line, suitable for `jq` pipelines):

```bash
gitreaper -json https://example.com/.git | jq .
```

```json
{"repo_url":"https://example.com/.git","commit_hash":"89fc077a...","file_path":".env","line_num":14,"line":"JWT_SECRET=s3cr3tV4lue!","rule_name":"generic-secret","rule_desc":"Generic secret assignment"}
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-urls FILE` | | File of URLs to scan (one per line) |
| `-workers N` | `5` | Repos to scan concurrently |
| `-blob-workers N` | `10` | Concurrent blob fetches per repo |
| `-timeout D` | `30s` | HTTP request timeout (e.g. `10s`, `2m`) |
| `-max-blob N` | `1048576` | Max blob size to scan in bytes (`0` = unlimited) |
| `-max-pack N` | `104857600` | Max pack file to download in bytes (`0` = unlimited) |
| `-max-refs N` | `0` | Max refs to walk per repo (`0` = unlimited) |
| `-repo-timeout D` | `0` | Per-repo time limit (`0` = unlimited, e.g. `60s`) |
| `-no-history` | | Scan HEAD commit only, skip full history |
| `-no-fp-reduction` | | Disable false-positive filtering, report all raw matches |
| `-json` | | Output findings as NDJSON |
| `-content` | | Include full file content in JSON findings |
| `-o FILE` | | Write output to file instead of stdout |
| `-out-dir DIR` | | Write per-target NDJSON to `DIR/<host>.json` |
| `-dump DIR` | | Dump HEAD working tree of each repo to `DIR/<host>/` |
| `-rules FILE` | | JSON rules file to merge with built-in rules |
| `-no-default-rules` | | Disable built-in rules (requires `-rules`) |
| `-progress` | | Show live status bar on stderr |
| `-v` | | Verbose logging |

## Rules

All rules live in a single file, `internal/scan/rules.json`, embedded at compile time. It's a JSON array of **groups**, each holding related rules:

```json
[
  {
    "group": "tokens-aws",
    "severity": "critical",
    "tags": ["cloud", "aws"],
    "enabled": true,
    "rules": [
      {"type": "token", "name": "aws-access-key-id", "desc": "AWS Access Key ID", "pattern": "AKIA[0-9A-Z]{16}"},
      {
        "type": "context",
        "name": "aws-secret-key-assignment",
        "desc": "AWS secret key in an assignment",
        "pattern": "aws_secret_access_key\\s*[=:]\\s*\\S+",
        "validate": {"entropy_min": 3.5, "not_placeholder": true}
      }
    ]
  }
]
```

`enabled` defaults to `true` and controls whether the group is active out of the box — set it to `false` for noisy/opt-in groups; they can still be turned on with `-enable-groups`.

Each rule has a `type`:

| Type | Behaviour |
|------|-----------|
| `token` | Matches a self-identifying value (vendor-specific prefix, e.g. `AKIA...`). No FP filtering — the prefix is sufficient evidence. |
| `context` | Matches a `key=value`-style assignment. The value is extracted (via `extract`, or a default `key=value` extractor) and checked against `validate` to suppress false positives. |
| `path` | Matches the file path instead of file content. |

`validate` (context rules only) enables one or more checks on the extracted value: `entropy_min`, `not_placeholder`, `not_runtime_value` (rejects `getenv()`/`process.env`/etc.), `not_template_var` (rejects `${VAR}`, `{{var}}`), `not_all_same_char`, `not_function_value`, `not_bare_identifier`, `not_property_access`, or `extract_mode: "url_cred"` (validates `user:pass@host` URL credentials instead).

### Using custom rules

```bash
# Merge a custom file with built-in rules
gitreaper -rules my-rules.json https://example.com/.git

# Use only custom rules
gitreaper -rules my-rules.json -no-default-rules https://example.com/.git
```

### Importing from secrets-patterns-db

```bash
# Install PyYAML
python3 -m venv /tmp/gr-venv && /tmp/gr-venv/bin/pip install pyyaml

# Import (high-confidence rules only by default)
PYTHON3=/tmp/gr-venv/bin/python3 ./scripts/import-secrets-db.sh -o rules-community.json

# Use the result
gitreaper -rules rules-community.json https://example.com/.git

# Options
./scripts/import-secrets-db.sh -h
```

The script downloads the upstream YAML, strips RE2-incompatible patterns (lookaheads, backreferences), deduplicates against the names already in `internal/scan/rules.json`, and writes a single-group rules file ready for `-rules`. High-confidence entries become `token` rules; low-confidence entries become `context` rules with generic FP-reduction `validate` checks. To fold the result into the built-in rule set permanently, merge its group into `internal/scan/rules.json` by hand and rebuild.

| Option | Default | Description |
|--------|---------|-------------|
| `-o FILE` | `rules-community.json` | Output file |
| `-c LEVEL` | `high` | Confidence filter: `high`, `low`, or `all` |
| `-p PREFIX` | `ext-` | Name prefix for imported rules |
| `-f FILE` | | Use a local YAML file instead of downloading |
| `--no-dedup` | | Skip deduplication against built-in rules |

## Mass scanning

For bulk scans, tune limits to avoid spending too long on any one target:

```bash
gitreaper \
  -urls targets.txt \
  -workers 20 \
  -repo-timeout 120s \
  -max-refs 50 \
  -json \
  -out-dir results/ \
  -progress
```

`-max-refs` limits history depth per repo. `-repo-timeout` hard-kills slow scans. `-out-dir` writes per-target NDJSON so partial results are preserved if the run is interrupted.

## Dump mode

`-dump DIR` writes the HEAD-state working tree of each repo to disk, mirroring the structure a developer would see with `git checkout`:

```bash
gitreaper -dump ./dumped https://example.com/.git
# Creates: ./dumped/example.com/src/config.js, .env, etc.
```

Useful for manual review or feeding into other static analysis tools.

## Legal

Only scan systems you own or have explicit written permission to test. 
