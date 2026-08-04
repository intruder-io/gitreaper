#!/usr/bin/env bash
set -euo pipefail

DEPTH=1

usage() {
  echo "Usage: $0 [-n count] <base-url>"
  echo ""
  echo "Extract committer emails from an exposed .git directory by fetching"
  echo "and parsing commit objects."
  echo ""
  echo "  base-url     Root URL of the site (e.g. https://example.com)"
  echo "  -n count     Number of commits to walk (default: 1, 0 = all reachable)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) DEPTH="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*) echo "error: unknown option $1" >&2; usage ;;
    *)  break ;;
  esac
done

[[ $# -lt 1 ]] && usage

BASE_URL="${1%/}"
GIT_URL="${BASE_URL}/.git"

fetch() {
  curl -sS -f -L --max-time 10 "$1" 2>/dev/null
}

fetch_binary() {
  curl -sS -f -L --max-time 10 --output "$2" "$1" 2>/dev/null
}

decompress_object() {
  python3 -c "
import zlib, sys
data = zlib.decompress(open(sys.argv[1], 'rb').read())
idx = data.index(b'\x00')
sys.stdout.buffer.write(data[idx+1:])
" "$1"
}

resolve_ref() {
  local ref_content
  ref_content=$(fetch "${GIT_URL}/$1") || return 1
  echo "$ref_content" | tr -d '[:space:]'
}

resolve_commit_hash() {
  local head
  head=$(fetch "${GIT_URL}/HEAD") || {
    echo "error: could not fetch ${GIT_URL}/HEAD" >&2
    return 1
  }

  if [[ "$head" =~ ^ref:\ (.+) ]]; then
    local ref="${BASH_REMATCH[1]}"
    local hash
    hash=$(resolve_ref "$ref" 2>/dev/null) || true

    if [[ -z "$hash" || ! "$hash" =~ ^[0-9a-f]{40}$ ]]; then
      local packed
      packed=$(fetch "${GIT_URL}/packed-refs") || {
        echo "error: could not resolve ref $ref" >&2
        return 1
      }
      hash=$(echo "$packed" | awk -v ref="$ref" '$2 == ref { print $1 }' | head -1)
    fi

    if [[ -z "$hash" ]]; then
      echo "error: could not resolve ref $ref" >&2
      return 1
    fi
    echo "$hash"
  elif [[ "$head" =~ ^[0-9a-f]{40} ]]; then
    echo "${head:0:40}"
  else
    echo "error: unexpected HEAD content" >&2
    return 1
  fi
}

fetch_object() {
  local hash="$1"
  local prefix="${hash:0:2}"
  local suffix="${hash:2}"
  local url="${GIT_URL}/objects/${prefix}/${suffix}"
  local tmpfile
  tmpfile=$(mktemp)

  if fetch_binary "$url" "$tmpfile"; then
    decompress_object "$tmpfile"
    rm -f "$tmpfile"
    return 0
  fi

  rm -f "$tmpfile"
  return 1
}

parse_emails() {
  sed -n \
    -e 's/^author .* <\([^>]*\)>.*/author \1/p' \
    -e 's/^committer .* <\([^>]*\)>.*/committer \1/p'
}

extract_parent() {
  sed -n 's/^parent \([0-9a-f]\{40\}\).*/\1/p' | head -1
}

HASH=$(resolve_commit_hash) || exit 1

COUNT=0
while true; do
  COMMIT_DATA=$(fetch_object "$HASH") || {
    echo "error: could not fetch commit object $HASH" >&2
    break
  }

  EMAILS=$(echo "$COMMIT_DATA" | parse_emails)
  if [[ -n "$EMAILS" ]]; then
    while IFS= read -r line; do
      echo "${HASH:0:8} $line"
    done <<< "$EMAILS"
  fi

  COUNT=$((COUNT + 1))
  if [[ "$DEPTH" -ne 0 && "$COUNT" -ge "$DEPTH" ]]; then
    break
  fi

  PARENT=$(echo "$COMMIT_DATA" | extract_parent)
  if [[ -z "$PARENT" ]]; then
    break
  fi
  HASH="$PARENT"
done
