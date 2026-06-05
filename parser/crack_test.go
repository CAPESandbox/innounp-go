package parser

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"testing"
)

// Helper to construct a mock protected SETUP.0 stream on disk
func createMockProtectedInnoExe(t *testing.T, password string) string {
	tmpFile, err := os.CreateTemp("", "mock_protected_inno_*.exe")
	if err != nil {
		t.Fatalf("failed to create temp: %v", err)
	}
	defer tmpFile.Close()

	// 1. ExeHeaderOffset Padding
	padding := make([]byte, SetupLdrExeHeaderOffset)
	tmpFile.Write(padding)

	// 2. ExeHeader
	tableOffset := int32(512)
	exeHeader := SetupLdrExeHeader{
		ID:                   SetupLdrExeHeaderID,
		OffsetTableOffset:    tableOffset,
		NotOffsetTableOffset: ^tableOffset,
	}
	binary.Write(tmpFile, binary.LittleEndian, &exeHeader)

	// 3. Offset Table at 512
	tmpFile.Seek(int64(tableOffset), io.SeekStart)
	var id [12]byte
	copy(id[:], offsetTableIDModern)

	tbl := SetupLdrOffsetTable32{
		ID:        id,
		Version:   1,
		Offset0:   1000, // SETUP.0 starts at 1000
		Offset1:   1000,
		TotalSize: 10000,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &tbl)
	tableBytes := buf.Bytes()[:44]
	calcCRC := crc32.ChecksumIEEE(tableBytes[:40])
	binary.LittleEndian.PutUint32(tableBytes[40:44], calcCRC)
	tmpFile.Write(tableBytes)

	// 4. Seek to SETUP.0 (1000) and write Signature String (64 bytes)
	tmpFile.Seek(1000, io.SeekStart)
	sigBytes := make([]byte, 64)
	copy(sigBytes, []byte("Inno Setup Setup Data (5.9.9) (u)"))
	tmpFile.Write(sigBytes)

	// 5. Serialize TSetupHeader Record Bytes with dynamic password checks
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	expectedHash := DerivePasswordHashSHA1(password, salt, true) // v5.5.0u is Unicode!

	headerRecord := &ParsedRecord{
		WideStrings: make([]string, 27),
		AnsiStrings: make([]string, 4),
		Fields:      make(map[string]interface{}),
	}
	headerRecord.Fields["NumLanguageEntries"] = uint32(0)
	headerRecord.Fields["NumCustomMessageEntries"] = uint32(0)
	headerRecord.Fields["NumPermissionEntries"] = uint32(0)
	headerRecord.Fields["NumTypeEntries"] = uint32(0)
	headerRecord.Fields["NumComponentEntries"] = uint32(0)
	headerRecord.Fields["NumTaskEntries"] = uint32(0)
	headerRecord.Fields["NumDirEntries"] = uint32(0)
	headerRecord.Fields["NumFileEntries"] = uint32(0)
	headerRecord.Fields["NumFileLocationEntries"] = uint32(0)
	headerRecord.Fields["NumIconEntries"] = uint32(0)
	headerRecord.Fields["NumIniEntries"] = uint32(0)
	headerRecord.Fields["NumRegistryEntries"] = uint32(0)
	headerRecord.Fields["NumInstallDeleteEntries"] = uint32(0)
	headerRecord.Fields["NumUninstallDeleteEntries"] = uint32(0)
	headerRecord.Fields["NumRunEntries"] = uint32(0)
	headerRecord.Fields["NumUninstallRunEntries"] = uint32(0)
	headerRecord.Fields["MinVersion"] = make([]byte, 10)
	headerRecord.Fields["OnlyBelowVersion"] = make([]byte, 10)
	headerRecord.Fields["BackColor"] = uint32(0)
	headerRecord.Fields["BackColor2"] = uint32(0)
	headerRecord.Fields["WizardImageBackColor"] = uint32(0)
	headerRecord.Fields["PasswordHash"] = expectedHash
	headerRecord.Fields["PasswordSalt"] = salt
	headerRecord.Fields["ExtraDiskSpaceRequired"] = int64(0)
	headerRecord.Fields["SlicesPerDisk"] = uint32(1)
	headerRecord.Fields["UninstallLogMode"] = uint8(0)
	headerRecord.Fields["DirExistsWarning"] = uint8(0)
	headerRecord.Fields["PrivilegesRequired"] = uint8(0)
	headerRecord.Fields["ShowLanguageDialog"] = uint8(0)
	headerRecord.Fields["LanguageDetectionMethod"] = uint8(0)
	headerRecord.Fields["CompressMethod"] = uint8(0)
	headerRecord.Fields["ArchitecturesAllowed"] = uint32(0)
	headerRecord.Fields["ArchitecturesInstallIn64BitMode"] = uint32(0)
	headerRecord.Fields["DisableDirPage"] = uint8(0)
	headerRecord.Fields["DisableProgramGroupPage"] = uint8(0)
	headerRecord.Fields["UninstallDisplaySize"] = int64(0)
	headerRecord.Fields["Options"] = uint32(0)

	// Serialize record into a zlib block
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)

	// WideStrings
	for i := 0; i < 27; i++ {
		binary.Write(zw, binary.LittleEndian, uint32(0))
	}
	// AnsiStrings
	for i := 0; i < 4; i++ {
		binary.Write(zw, binary.LittleEndian, uint32(0))
	}
	// Fixed Fields (write according to SchemaRegistry[9999]["TSetupHeader"] which falls back to 5500)
	schema := SchemaRegistry[5500]["TSetupHeader"]
	for _, field := range schema.FixedFields {
		val := headerRecord.Fields[field.Name]
		switch field.Type {
		case FieldInt8, FieldEnum:
			binary.Write(zw, binary.LittleEndian, val.(uint8))
		case FieldInt16:
			binary.Write(zw, binary.LittleEndian, val.(int16))
		case FieldInt32, FieldBitset:
			if field.Size == 8 {
				binary.Write(zw, binary.LittleEndian, val.(uint64))
			} else {
				binary.Write(zw, binary.LittleEndian, val.(uint32))
			}
		case FieldInt64:
			binary.Write(zw, binary.LittleEndian, val.(int64))
		case FieldBytes:
			zw.Write(val.([]byte))
		}
	}
	zw.Close()

	// Wrap in CRC-chunking
	chunkedPayload := createChunk(zlibBuf.Bytes())

	// Block Header
	hdrBytes := make([]byte, 5)
	binary.LittleEndian.PutUint32(hdrBytes[0:4], uint32(len(chunkedPayload)))
	hdrBytes[4] = 1 // compressed

	hdrCRC := crc32.ChecksumIEEE(hdrBytes)

	// Seek to SETUP.0 block header (1000 + 64 = 1064) and write
	tmpFile.Seek(1064, io.SeekStart)
	binary.Write(tmpFile, binary.LittleEndian, hdrCRC)
	tmpFile.Write(hdrBytes)
	tmpFile.Write(chunkedPayload)

	return tmpFile.Name()
}

func TestCrackPassword_Success(t *testing.T) {
	correctPassword := "MalwareDec123"
	filePath := createMockProtectedInnoExe(t, correctPassword)
	defer os.Remove(filePath)

	wordlist := []string{
		"admin", "setup", "password", "infected", "MalwareDec123", "cracked",
	}

	result, err := CrackPassword(filePath, wordlist)
	if err != nil {
		t.Fatalf("expected successful cracking run, got error: %v", err)
	}

	if !result.PasswordFound {
		t.Fatal("expected password to be successfully recovered, but it failed")
	}

	if result.Password != correctPassword {
		t.Errorf("expected cracked password to be %q, got %q", correctPassword, result.Password)
	}

	if result.HashType != "SHA-1" {
		t.Errorf("expected hash type 'SHA-1', got %q", result.HashType)
	}
}

func TestCrackPassword_NotFound(t *testing.T) {
	filePath := createMockProtectedInnoExe(t, "SecretUniqueKey")
	defer os.Remove(filePath)

	wordlist := []string{"admin", "setup", "password", "123456"}

	result, err := CrackPassword(filePath, wordlist)
	if err != nil {
		t.Fatalf("expected successful cracking run, got error: %v", err)
	}

	if result.PasswordFound {
		t.Errorf("expected password to not be found, but it claimed to find: %q", result.Password)
	}
}
