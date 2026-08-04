package git

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// IndexEntry is a single file entry from a parsed .git/index file.
type IndexEntry struct {
	SHA  string // 40-char hex SHA1 of the blob object
	Path string // repo-relative path (e.g. "src/main.go")
}

// ParseGitIndex parses a raw .git/index binary blob (format versions 2 and 3)
// and returns the (path, sha) pairs for every file in the staging area.
//
// Version 4 (delta-compressed names, git ≥ 2.20) returns an error.
// Extensions and the trailing checksum are ignored.
func ParseGitIndex(data []byte) ([]IndexEntry, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("index file too short (%d bytes)", len(data))
	}
	if !bytes.Equal(data[0:4], []byte("DIRC")) {
		return nil, fmt.Errorf("invalid index magic %q", data[0:4])
	}

	version := binary.BigEndian.Uint32(data[4:8])
	if version == 4 {
		return nil, fmt.Errorf("index version 4 (delta-compressed names) not supported")
	}
	if version < 2 || version > 3 {
		return nil, fmt.Errorf("unsupported index version %d", version)
	}

	numEntries := int(binary.BigEndian.Uint32(data[8:12]))
	entries := make([]IndexEntry, 0, numEntries)

	pos := 12
	for i := 0; i < numEntries; i++ {
		entryStart := pos

		// Fixed fields: 40 bytes metadata + 20 bytes SHA1 + 2 bytes flags = 62 bytes
		if pos+62 > len(data) {
			break
		}

		shaRaw := data[pos+40 : pos+60]
		sha := hex.EncodeToString(shaRaw)
		flags := binary.BigEndian.Uint16(data[pos+60 : pos+62])
		pos += 62

		// Version 3: 2-byte extended flags when bit 14 of the standard flags is set.
		if version == 3 && flags&0x4000 != 0 {
			if pos+2 > len(data) {
				break
			}
			pos += 2
		}

		// NUL-terminated path name.
		nul := bytes.IndexByte(data[pos:], 0)
		if nul < 0 {
			break
		}
		path := string(data[pos : pos+nul])
		pos += nul + 1 // consume name + NUL

		// Pad the total entry length to the next multiple of 8, measured from
		// the start of the entry.  Minimum one NUL byte is already consumed above.
		if r := (pos - entryStart) % 8; r != 0 {
			pos += 8 - r
		}

		if path == "" || !isValidSHA(sha) {
			continue
		}
		entries = append(entries, IndexEntry{SHA: sha, Path: path})
	}

	return entries, nil
}
