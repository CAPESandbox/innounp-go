package parser

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// EnableDebugLogging is a globally accessible flag to toggle debug output.
var EnableDebugLogging = false

// debugPrintf prints formatting output only if EnableDebugLogging is enabled.
func debugPrintf(format string, a ...interface{}) {
	if EnableDebugLogging {
		fmt.Printf(format, a...)
	}
}

// ReadRecord sequentially parses strings and fixed fields based on a RecordSchema.
// If isUnicode is false (ANSI installer), it dynamically overrides the schema to
// read all wide strings as standard AnsiStrings on the fly, matching Delphi compiler directives.
func ReadRecord(r io.Reader, schema RecordSchema, isUnicode bool) (*ParsedRecord, error) {
	numWideStrings := schema.NumWideStrings
	numAnsiStrings := schema.NumAnsiStrings

	if !isUnicode {
		numAnsiStrings = numWideStrings + numAnsiStrings
		numWideStrings = 0
	}

	record := &ParsedRecord{
		WideStrings: make([]string, 0, numWideStrings),
		AnsiStrings: make([]string, 0, numAnsiStrings),
		Fields:      make(map[string]interface{}),
	}

	// 1. Read Wide Strings (UTF-16LE)
	for i := 0; i < numWideStrings; i++ {
		var strLen uint32
		if err := binary.Read(r, binary.LittleEndian, &strLen); err != nil {
			return nil, fmt.Errorf("failed to read WideString %d length: %w", i, err)
		}

		if strLen > 0 {
			strBytes := make([]byte, strLen)
			if _, err := io.ReadFull(r, strBytes); err != nil {
				return nil, fmt.Errorf("failed to read WideString %d bytes: %w", i, err)
			}
			record.WideStrings = append(record.WideStrings, decodeUTF16LE(strBytes))
		} else {
			record.WideStrings = append(record.WideStrings, "")
		}
	}

	// 2. Read Ansi Strings (ASCII / Windows-1252 fallback)
	for i := 0; i < numAnsiStrings; i++ {
		var strLen uint32
		if err := binary.Read(r, binary.LittleEndian, &strLen); err != nil {
			return nil, fmt.Errorf("failed to read AnsiString %d length: %w", i, err)
		}

		if EnableDebugLogging {
			fmt.Printf("[DEBUG-STR] Reading AnsiString %d: length %d\n", i, strLen)
		}

		if strLen > 0 {
			strBytes := make([]byte, strLen)
			if _, err := io.ReadFull(r, strBytes); err != nil {
				return nil, fmt.Errorf("failed to read AnsiString %d bytes: %w", i, err)
			}
			record.AnsiStrings = append(record.AnsiStrings, string(strBytes))
			if EnableDebugLogging {
				disp := string(strBytes)
				if len(disp) > 50 {
					disp = disp[:50] + "..."
				}
				fmt.Printf("[DEBUG-STR] AnsiString %d content: %q\n", i, disp)
			}
		} else {
			record.AnsiStrings = append(record.AnsiStrings, "")
		}
	}

	// 3. Read Fixed-Size Fields sequentially
	for _, field := range schema.FixedFields {
		switch field.Type {
		case FieldInt8, FieldEnum:
			var val uint8
			if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
				return nil, fmt.Errorf("failed to read field %s (Int8): %w", field.Name, err)
			}
			record.Fields[field.Name] = val

		case FieldInt16:
			var val int16
			if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
				return nil, fmt.Errorf("failed to read field %s (Int16): %w", field.Name, err)
			}
			record.Fields[field.Name] = val

		case FieldInt32, FieldBitset:
			if field.Size == 8 {
				// Some options/sets are 64-bit (8 bytes) on newer versions
				var val uint64
				if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
					return nil, fmt.Errorf("failed to read 64-bit field %s (Bitset): %w", field.Name, err)
				}
				record.Fields[field.Name] = val
			} else if field.Size == 7 {
				// Read exactly 7 bytes for a 56-bit set and pad to uint64
				buf := make([]byte, 7)
				if _, err := io.ReadFull(r, buf); err != nil {
					return nil, fmt.Errorf("failed to read 56-bit field %s (Bitset): %w", field.Name, err)
				}
				// Pad with 1 trailing zero byte to make 8 bytes (little-endian)
				paddedBuf := []byte{buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], 0}
				val := binary.LittleEndian.Uint64(paddedBuf)
				record.Fields[field.Name] = val
			} else if field.Size == 6 {
				// Read exactly 6 bytes for a 48-bit set and pad to uint64
				buf := make([]byte, 6)
				if _, err := io.ReadFull(r, buf); err != nil {
					return nil, fmt.Errorf("failed to read 48-bit field %s (Bitset): %w", field.Name, err)
				}
				// Pad with 2 trailing zero bytes to make 8 bytes (little-endian)
				paddedBuf := []byte{buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], 0, 0}
				val := binary.LittleEndian.Uint64(paddedBuf)
				record.Fields[field.Name] = val
			} else if field.Size == 2 {
				var val uint16
				if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
					return nil, fmt.Errorf("failed to read 16-bit field %s (Bitset): %w", field.Name, err)
				}
				record.Fields[field.Name] = uint32(val)
			} else if field.Size == 1 {
				var val uint8
				if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
					return nil, fmt.Errorf("failed to read 8-bit field %s (Bitset): %w", field.Name, err)
				}
				record.Fields[field.Name] = uint32(val)
			} else {
				var val uint32
				if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
					return nil, fmt.Errorf("failed to read field %s (Int32): %w", field.Name, err)
				}
				record.Fields[field.Name] = val
			}

		case FieldInt64:
			var val int64
			if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
				return nil, fmt.Errorf("failed to read field %s (Int64): %w", field.Name, err)
			}
			record.Fields[field.Name] = val

		case FieldBytes:
			buf := make([]byte, field.Size)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, fmt.Errorf("failed to read field %s (Bytes size %d): %w", field.Name, field.Size, err)
			}
			record.Fields[field.Name] = buf

		default:
			return nil, fmt.Errorf("unsupported field type for field %s", field.Name)
		}
	}

	return record, nil
}

// decodeUTF16LE converts a little-endian UTF-16 byte slice to a Go UTF-8 string.
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16s))
}
