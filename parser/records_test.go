package parser

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// Helper to encode a string into UTF-16LE bytes with a 4-byte length prefix
func encodeUTF16LEBytes(s string) []byte {
	buf := new(bytes.Buffer)
	runes := []rune(s)
	// Calculate size in bytes (each character is 2 bytes in UTF-16)
	size := len(runes) * 2
	binary.Write(buf, binary.LittleEndian, uint32(size))
	for _, r := range runes {
		// Simple BMP encoding (sufficient for standard text tests)
		binary.Write(buf, binary.LittleEndian, uint16(r))
	}
	return buf.Bytes()
}

// Helper to encode an ANSI string with 4-byte length prefix
func encodeAnsiBytes(s string) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(s)))
	buf.Write([]byte(s))
	return buf.Bytes()
}

func TestReadRecord_Success(t *testing.T) {
	// 1. Define a robust mock schema
	schema := RecordSchema{
		NumWideStrings: 2,
		NumAnsiStrings: 1,
		FixedFields: []FieldSchema{
			{"FieldA", FieldInt32, 4},
			{"FieldB", FieldInt16, 2},
			{"FieldC", FieldInt8, 1},
			{"FieldD", FieldBytes, 5},
			{"FieldE", FieldBitset, 8}, // 64-bit bitset
		},
	}

	// 2. Build the raw binary stream
	buf := new(bytes.Buffer)

	// WideStrings
	buf.Write(encodeUTF16LEBytes("Hello World"))
	buf.Write(encodeUTF16LEBytes("InnoUnp-Go"))

	// AnsiString
	buf.Write(encodeAnsiBytes("ANSI Standard Text"))

	// Fixed fields
	binary.Write(buf, binary.LittleEndian, int32(99999))  // FieldA
	binary.Write(buf, binary.LittleEndian, int16(-300))   // FieldB
	binary.Write(buf, binary.LittleEndian, uint8(42))     // FieldC
	buf.Write([]byte{0x10, 0x20, 0x30, 0x40, 0x50})       // FieldD (Bytes)
	binary.Write(buf, binary.LittleEndian, uint64(0xABC)) // FieldE (64-bit Bitset)

	// 3. Parse the record
	record, err := ReadRecord(buf, schema, true)
	if err != nil {
		t.Fatalf("failed to parse record: %v", err)
	}

	// 4. Assert WideStrings
	if len(record.WideStrings) != 2 {
		t.Fatalf("expected 2 wide strings, got %d", len(record.WideStrings))
	}
	if record.WideStrings[0] != "Hello World" {
		t.Errorf("expected string 'Hello World', got %q", record.WideStrings[0])
	}
	if record.WideStrings[1] != "InnoUnp-Go" {
		t.Errorf("expected string 'InnoUnp-Go', got %q", record.WideStrings[1])
	}

	// 5. Assert AnsiStrings
	if len(record.AnsiStrings) != 1 {
		t.Fatalf("expected 1 ansi string, got %d", len(record.AnsiStrings))
	}
	if record.AnsiStrings[0] != "ANSI Standard Text" {
		t.Errorf("expected string 'ANSI Standard Text', got %q", record.AnsiStrings[0])
	}

	// 6. Assert Fixed-size fields
	if record.Fields["FieldA"] != uint32(99999) {
		t.Errorf("FieldA mismatch: expected %d, got %v", 99999, record.Fields["FieldA"])
	}
	if record.Fields["FieldB"] != int16(-300) {
		t.Errorf("FieldB mismatch: expected %d, got %v", -300, record.Fields["FieldB"])
	}
	if record.Fields["FieldC"] != uint8(42) {
		t.Errorf("FieldC mismatch: expected %d, got %v", 42, record.Fields["FieldC"])
	}

	expectedBytes := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	if !reflect.DeepEqual(record.Fields["FieldD"], expectedBytes) {
		t.Errorf("FieldD (Bytes) mismatch: expected %v, got %v", expectedBytes, record.Fields["FieldD"])
	}

	if record.Fields["FieldE"] != uint64(0xABC) {
		t.Errorf("FieldE mismatch: expected 0xABC, got %v", record.Fields["FieldE"])
	}
}

func TestReadRecord_TruncatedStream_Failure(t *testing.T) {
	schema := RecordSchema{
		NumWideStrings: 1,
		FixedFields: []FieldSchema{
			{"FieldA", FieldInt32, 4},
		},
	}

	// Intentionally truncated: missing fixed FieldA bytes
	buf := new(bytes.Buffer)
	buf.Write(encodeUTF16LEBytes("Shorty"))

	_, err := ReadRecord(buf, schema, true)
	if err == nil {
		t.Error("expected parsing failure due to truncated stream, but got success")
	}
}

func TestGetRecordSchema_Version7000(t *testing.T) {
	// Verify that the schema loads for Inno Setup 7.0 (v7000)
	headerSchema, ok := GetRecordSchema(7000, "TSetupHeader", true)
	if !ok {
		t.Fatalf("failed to get schema for TSetupHeader under version 7000")
	}

	if headerSchema.NumWideStrings != 39 {
		t.Errorf("expected 39 wide strings in v7000 TSetupHeader, got %d", headerSchema.NumWideStrings)
	}

	// Verify new field CompiledCodeVersion exists
	foundCompiledCodeVersion := false
	for _, field := range headerSchema.FixedFields {
		if field.Name == "CompiledCodeVersion" {
			foundCompiledCodeVersion = true
			if field.Type != FieldInt32 || field.Size != 4 {
				t.Errorf("CompiledCodeVersion field schema mismatch: expected Type=FieldInt32, Size=4, got Type=%v, Size=%d", field.Type, field.Size)
			}
		}
	}
	if !foundCompiledCodeVersion {
		t.Errorf("CompiledCodeVersion field not found in v7000 TSetupHeader schema")
	}

	// Verify that the file entry schema has 15 wide strings, 1 ansi string, and verification fields
	fileSchema, ok := GetRecordSchema(7000, "TSetupFileEntry", true)
	if !ok {
		t.Fatalf("failed to get schema for TSetupFileEntry under version 7000")
	}

	if fileSchema.NumWideStrings != 15 {
		t.Errorf("expected 15 wide strings in v7000 TSetupFileEntry, got %d", fileSchema.NumWideStrings)
	}
	if fileSchema.NumAnsiStrings != 1 {
		t.Errorf("expected 1 ansi string in v7000 TSetupFileEntry, got %d", fileSchema.NumAnsiStrings)
	}

	// Verify that the location entry has StartOffset as FieldInt64 (8 bytes)
	locSchema, ok := GetRecordSchema(7000, "TSetupFileLocationEntry", true)
	if !ok {
		t.Fatalf("failed to get schema for TSetupFileLocationEntry under version 7000")
	}

	foundStartOffset := false
	for _, field := range locSchema.FixedFields {
		if field.Name == "StartOffset" {
			foundStartOffset = true
			if field.Type != FieldInt64 || field.Size != 8 {
				t.Errorf("StartOffset field schema mismatch: expected Type=FieldInt64, Size=8, got Type=%v, Size=%d", field.Type, field.Size)
			}
		}
	}
	if !foundStartOffset {
		t.Errorf("StartOffset field not found in v7000 TSetupFileLocationEntry schema")
	}
}
