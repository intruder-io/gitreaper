package git

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// ObjType represents a git object type.
type ObjType int

const (
	ObjCommit   ObjType = 1
	ObjTree     ObjType = 2
	ObjBlob     ObjType = 3
	ObjTag      ObjType = 4
	ObjOfsDelta ObjType = 6
	ObjRefDelta ObjType = 7
)

// Object is a decoded git object.
type Object struct {
	Type ObjType
	Data []byte
}

// ParseLooseObject decompresses and parses a loose git object file.
// Loose objects are stored as zlib-compressed "type SP size NUL data".
func ParseLooseObject(compressed []byte) (*Object, error) {
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("zlib open: %w", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("zlib read: %w", err)
	}
	return parseRawObject(raw)
}

func parseRawObject(raw []byte) (*Object, error) {
	nul := bytes.IndexByte(raw, 0)
	if nul < 0 {
		return nil, fmt.Errorf("object missing NUL separator")
	}
	parts := strings.SplitN(string(raw[:nul]), " ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid object header: %q", raw[:nul])
	}
	var t ObjType
	switch parts[0] {
	case "commit":
		t = ObjCommit
	case "tree":
		t = ObjTree
	case "blob":
		t = ObjBlob
	case "tag":
		t = ObjTag
	default:
		return nil, fmt.Errorf("unknown object type %q", parts[0])
	}
	return &Object{Type: t, Data: raw[nul+1:]}, nil
}

// DecompressZlib decompresses a zlib-encoded byte slice.
func DecompressZlib(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// Commit is a parsed git commit.
type Commit struct {
	Tree    string
	Parents []string
}

// ParseCommit parses a commit object's data.
func ParseCommit(data []byte) (*Commit, error) {
	c := &Commit{}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "tree "):
			c.Tree = strings.TrimPrefix(line, "tree ")
		case strings.HasPrefix(line, "parent "):
			c.Parents = append(c.Parents, strings.TrimPrefix(line, "parent "))
		case line == "":
			return c, nil // message follows blank line; stop here
		}
	}
	if c.Tree == "" {
		return nil, fmt.Errorf("commit missing tree header")
	}
	return c, nil
}

// Tag is a parsed git tag object.
type Tag struct {
	Object string // SHA of the tagged object
	Type   string // type name of the tagged object
}

// ParseTag parses a tag object's data.
func ParseTag(data []byte) (*Tag, error) {
	t := &Tag{}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "object "):
			t.Object = strings.TrimPrefix(line, "object ")
		case strings.HasPrefix(line, "type "):
			t.Type = strings.TrimPrefix(line, "type ")
		case line == "":
			return t, nil
		}
	}
	return t, nil
}

// TreeEntry is one entry in a git tree object.
type TreeEntry struct {
	Mode   string
	Name   string
	SHA    string // hex-encoded
	IsTree bool
}

// ParseTree parses a tree object's binary data.
// Format: repeated { mode SP name NUL sha[20] }
func ParseTree(data []byte) ([]TreeEntry, error) {
	var entries []TreeEntry
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp < 0 {
			break
		}
		mode := string(data[:sp])
		data = data[sp+1:]

		nul := bytes.IndexByte(data, 0)
		if nul < 0 {
			break
		}
		name := string(data[:nul])
		data = data[nul+1:]

		if len(data) < 20 {
			break
		}
		sha := hex.EncodeToString(data[:20])
		data = data[20:]

		entries = append(entries, TreeEntry{
			Mode:   mode,
			Name:   name,
			SHA:    sha,
			IsTree: mode == "40000" || mode == "040000", // git stores dir mode as "40000" (no leading zero)
		})
	}
	return entries, nil
}

// ApplyDelta applies a git binary delta to a base object and returns the result.
// Delta format: src-size (varint), target-size (varint), then instructions.
func ApplyDelta(base, delta []byte) ([]byte, error) {
	r := bytes.NewReader(delta)

	srcSize, err := readDeltaVarInt(r)
	if err != nil {
		return nil, fmt.Errorf("delta src size: %w", err)
	}
	if uint64(len(base)) != srcSize {
		return nil, fmt.Errorf("delta src size mismatch: got %d want %d", len(base), srcSize)
	}

	targetSize, err := readDeltaVarInt(r)
	if err != nil {
		return nil, fmt.Errorf("delta target size: %w", err)
	}

	result := make([]byte, 0, targetSize)

	for r.Len() > 0 {
		cmd, err := r.ReadByte()
		if err != nil {
			break
		}

		if cmd&0x80 != 0 {
			// COPY from base: bits 0-3 encode which of 4 offset bytes follow,
			// bits 4-6 encode which of 3 size bytes follow.
			var offset, size uint32
			for i := uint(0); i < 4; i++ {
				if cmd&(1<<i) != 0 {
					b, _ := r.ReadByte()
					offset |= uint32(b) << (8 * i)
				}
			}
			for i := uint(0); i < 3; i++ {
				if cmd&(1<<(4+i)) != 0 {
					b, _ := r.ReadByte()
					size |= uint32(b) << (8 * i)
				}
			}
			if size == 0 {
				size = 0x10000
			}
			if int(offset)+int(size) > len(base) {
				return nil, fmt.Errorf("delta COPY out of bounds: offset=%d size=%d baselen=%d", offset, size, len(base))
			}
			result = append(result, base[offset:offset+size]...)
		} else if cmd > 0 {
			// INSERT: low 7 bits = number of literal bytes that follow
			buf := make([]byte, cmd)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, fmt.Errorf("delta INSERT: %w", err)
			}
			result = append(result, buf...)
		}
		// cmd == 0 is reserved/error; ignore
	}

	return result, nil
}

// readDeltaVarInt reads a variable-length integer from the delta stream.
// Each byte contributes 7 bits; MSB set means more bytes follow.
func readDeltaVarInt(r *bytes.Reader) (uint64, error) {
	var val uint64
	var shift uint
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		val |= uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	return val, nil
}

// ObjTypeName returns the human-readable name for a git object type.
func ObjTypeName(t ObjType) string {
	switch t {
	case ObjCommit:
		return "commit"
	case ObjTree:
		return "tree"
	case ObjBlob:
		return "blob"
	case ObjTag:
		return "tag"
	case ObjOfsDelta:
		return "ofs_delta"
	case ObjRefDelta:
		return "ref_delta"
	default:
		return fmt.Sprintf("type(%d)", int(t))
	}
}
