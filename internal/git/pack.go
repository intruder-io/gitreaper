package git

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// PackIndex maps object SHA (hex) to its byte offset inside a pack file.
type PackIndex struct {
	Entries map[string]int64
}

// ParsePackIndex parses a git pack index file (supports v1 and v2).
func ParsePackIndex(data []byte) (*PackIndex, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("pack index too short (%d bytes)", len(data))
	}
	// v2 magic: \xff\x74\x4f\x63
	if bytes.Equal(data[:4], []byte{0xff, 0x74, 0x4f, 0x63}) {
		ver := binary.BigEndian.Uint32(data[4:8])
		if ver != 2 {
			return nil, fmt.Errorf("unsupported pack index version %d", ver)
		}
		return parsePackIndexV2(data[8:])
	}
	// v1: starts directly with fan-out table
	return parsePackIndexV1(data)
}

func parsePackIndexV1(data []byte) (*PackIndex, error) {
	if len(data) < 256*4 {
		return nil, fmt.Errorf("v1 index too short for fan-out table")
	}
	total := int(binary.BigEndian.Uint32(data[255*4 : 256*4]))
	idx := &PackIndex{Entries: make(map[string]int64, total)}
	pos := 256 * 4
	for i := 0; i < total; i++ {
		if pos+24 > len(data) {
			break
		}
		off := binary.BigEndian.Uint32(data[pos : pos+4])
		sha := hex.EncodeToString(data[pos+4 : pos+24])
		idx.Entries[sha] = int64(off)
		pos += 24
	}
	return idx, nil
}

func parsePackIndexV2(data []byte) (*PackIndex, error) {
	// Layout after the 8-byte header already stripped:
	//   256 * uint32  fan-out table
	//   N * 20        SHA1 list (sorted)
	//   N * uint32    CRC32s (skipped)
	//   N * uint32    4-byte offsets (MSB=1 → index into large-offset table)
	//   M * uint64    large-offset table (optional)
	if len(data) < 256*4 {
		return nil, fmt.Errorf("v2 index too short for fan-out table")
	}
	total := int(binary.BigEndian.Uint32(data[255*4 : 256*4]))

	shaBase := 256 * 4
	crcBase := shaBase + total*20
	off4Base := crcBase + total*4
	largeBase := off4Base + total*4

	if largeBase > len(data) {
		return nil, fmt.Errorf("v2 index too short: need %d bytes, have %d", largeBase, len(data))
	}

	idx := &PackIndex{Entries: make(map[string]int64, total)}
	for i := 0; i < total; i++ {
		sha := hex.EncodeToString(data[shaBase+i*20 : shaBase+i*20+20])
		off32 := binary.BigEndian.Uint32(data[off4Base+i*4 : off4Base+i*4+4])

		var off int64
		if off32&0x80000000 != 0 {
			// MSB set → index into 8-byte large-offset table
			li := int(off32 & 0x7fffffff)
			if largeBase+li*8+8 > len(data) {
				return nil, fmt.Errorf("large offset index %d out of bounds", li)
			}
			off = int64(binary.BigEndian.Uint64(data[largeBase+li*8 : largeBase+li*8+8]))
		} else {
			off = int64(off32)
		}
		idx.Entries[sha] = off
	}
	return idx, nil
}

// Pack holds a fully-loaded pack file and its index.
type Pack struct {
	data []byte
	idx  *PackIndex
}

// NewPack wraps raw pack bytes and a parsed index.
func NewPack(packData []byte, idx *PackIndex) (*Pack, error) {
	if len(packData) < 12 {
		return nil, fmt.Errorf("pack file too short")
	}
	if !bytes.Equal(packData[:4], []byte{'P', 'A', 'C', 'K'}) {
		return nil, fmt.Errorf("invalid pack magic")
	}
	return &Pack{data: packData, idx: idx}, nil
}

// HasObject reports whether the pack contains the given SHA.
func (p *Pack) HasObject(sha string) bool {
	_, ok := p.idx.Entries[sha]
	return ok
}

// GetObject resolves an object by SHA, following any delta chains.
func (p *Pack) GetObject(sha string) (*Object, error) {
	offset, ok := p.idx.Entries[sha]
	if !ok {
		return nil, fmt.Errorf("SHA %s not in pack", sha)
	}
	return p.getAt(offset, 0)
}

// getAt reads a pack object at the given byte offset, resolving deltas recursively.
func (p *Pack) getAt(offset int64, depth int) (*Object, error) {
	if depth > 64 {
		return nil, fmt.Errorf("delta chain depth exceeded at offset %d", offset)
	}
	if offset >= int64(len(p.data)) {
		return nil, fmt.Errorf("offset %d out of pack bounds (%d bytes)", offset, len(p.data))
	}

	objType, payload, err := readPackHeader(p.data, offset)
	if err != nil {
		return nil, fmt.Errorf("read pack header at %d: %w", offset, err)
	}

	switch objType {
	case ObjCommit, ObjTree, ObjBlob, ObjTag:
		decompressed, err := DecompressZlib(payload)
		if err != nil {
			return nil, fmt.Errorf("decompress object at %d: %w", offset, err)
		}
		return &Object{Type: objType, Data: decompressed}, nil

	case ObjOfsDelta:
		negOff, n := readNegOffset(payload)
		base, err := p.getAt(offset-negOff, depth+1)
		if err != nil {
			return nil, fmt.Errorf("resolve ofs-delta base: %w", err)
		}
		delta, err := DecompressZlib(payload[n:])
		if err != nil {
			return nil, fmt.Errorf("decompress ofs-delta at %d: %w", offset, err)
		}
		result, err := ApplyDelta(base.Data, delta)
		if err != nil {
			return nil, fmt.Errorf("apply ofs-delta: %w", err)
		}
		return &Object{Type: base.Type, Data: result}, nil

	case ObjRefDelta:
		if len(payload) < 20 {
			return nil, fmt.Errorf("ref-delta payload too short at %d", offset)
		}
		baseSHA := hex.EncodeToString(payload[:20])
		base, err := p.GetObject(baseSHA)
		if err != nil {
			return nil, fmt.Errorf("resolve ref-delta base %s: %w", baseSHA, err)
		}
		delta, err := DecompressZlib(payload[20:])
		if err != nil {
			return nil, fmt.Errorf("decompress ref-delta at %d: %w", offset, err)
		}
		result, err := ApplyDelta(base.Data, delta)
		if err != nil {
			return nil, fmt.Errorf("apply ref-delta: %w", err)
		}
		return &Object{Type: base.Type, Data: result}, nil

	default:
		return nil, fmt.Errorf("unknown object type %d at offset %d", objType, offset)
	}
}

// readPackHeader parses the variable-length object header in a pack file.
// Returns the object type and the payload slice (starts right after the header).
//
// Header encoding:
//
//	byte 0:  MSB=continuation, bits 6-4=type, bits 3-0=size[3:0]
//	byte 1+: MSB=continuation, bits 6-0=size (7 bits each, little-endian)
func readPackHeader(data []byte, offset int64) (ObjType, []byte, error) {
	pos := int(offset)
	if pos >= len(data) {
		return 0, nil, fmt.Errorf("offset out of bounds")
	}

	b := data[pos]
	pos++

	objType := ObjType((b >> 4) & 0x7)
	// size is mostly informational (uncompressed size hint); we don't strictly need it
	for b&0x80 != 0 {
		if pos >= len(data) {
			return 0, nil, fmt.Errorf("truncated object header")
		}
		b = data[pos]
		pos++
	}

	return objType, data[pos:], nil
}

// readNegOffset reads the variable-length negative-offset encoding used by OBJ_OFS_DELTA.
// Returns (offset, bytes_consumed).
func readNegOffset(data []byte) (int64, int) {
	var off int64
	i := 0
	for {
		b := data[i]
		i++
		if i == 1 {
			off = int64(b & 0x7f)
		} else {
			off = ((off + 1) << 7) | int64(b&0x7f)
		}
		if b&0x80 == 0 {
			break
		}
	}
	return off, i
}
