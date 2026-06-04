package parser

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"testing"
)

// Helper to create a temporary mock Inno Setup file
func createMockInnoExe(t *testing.T, is64Bit bool, corruptCRC bool, corruptMagic bool) string {
	tmpFile, err := os.CreateTemp("", "mock_inno_*.exe")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// 1. Write dummy bytes up to ExeHeaderOffset (0x30)
	padding := make([]byte, SetupLdrExeHeaderOffset)
	if _, err := tmpFile.Write(padding); err != nil {
		t.Fatalf("failed to write padding: %v", err)
	}

	// 2. Write ExeHeader
	tableOffset := int32(512) // arbitrary location
	exeHeader := SetupLdrExeHeader{
		ID:                   SetupLdrExeHeaderID,
		OffsetTableOffset:    tableOffset,
		NotOffsetTableOffset: ^tableOffset,
	}
	if corruptMagic {
		exeHeader.ID = 0x11223344
	}

	if err := binary.Write(tmpFile, binary.LittleEndian, &exeHeader); err != nil {
		t.Fatalf("failed to write exe header: %v", err)
	}

	// 3. Seek to tableOffset and write mock table
	if _, err := tmpFile.Seek(int64(tableOffset), io.SeekStart); err != nil {
		t.Fatalf("failed to seek: %v", err)
	}

	var tableBytes []byte
	var id [12]byte
	copy(id[:], offsetTableIDModern)

	if is64Bit {
		tbl := SetupLdrOffsetTable64{
			ID:                  id,
			Version:             2,
			TotalSize:           1024 * 1024 * 5, // 5MB
			OffsetEXE:           1000,
			UncompressedSizeEXE: 1024 * 1024 * 10, // 10MB
			CRCEXE:              0x12345678,
			Offset0:             2000,
			Offset1:             3000,
			ReservedPadding:     0,
		}

		// Calculate CRC over the first 60 bytes
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.LittleEndian, &tbl); err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}
		tableBytes = buf.Bytes()[:64]

		calcCRC := crc32.ChecksumIEEE(tableBytes[:60])
		if corruptCRC {
			calcCRC ^= 0xFFFFFFFF
		}
		binary.LittleEndian.PutUint32(tableBytes[60:64], calcCRC)

	} else {
		tbl := SetupLdrOffsetTable32{
			ID:                  id,
			Version:             1,
			TotalSize:           1024 * 1024, // 1MB
			OffsetEXE:           500,
			UncompressedSizeEXE: 1024 * 1024 * 2,
			CRCEXE:              0x55555555,
			Offset0:             1000,
			Offset1:             1500,
		}

		// Calculate CRC over the first 40 bytes
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.LittleEndian, &tbl); err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}
		tableBytes = buf.Bytes()[:44]

		calcCRC := crc32.ChecksumIEEE(tableBytes[:40])
		if corruptCRC {
			calcCRC ^= 0xFFFFFFFF
		}
		binary.LittleEndian.PutUint32(tableBytes[40:44], calcCRC)
	}

	if _, err := tmpFile.Write(tableBytes); err != nil {
		t.Fatalf("failed to write table: %v", err)
	}

	return tmpFile.Name()
}

func TestParseSetupLdr_32Bit_Success(t *testing.T) {
	filePath := createMockInnoExe(t, false, false, false)
	defer os.Remove(filePath)

	table, err := ParseSetupLdr(filePath)
	if err != nil {
		t.Fatalf("expected successful parse, got error: %v", err)
	}

	if table.Is64Bit {
		t.Error("expected table format to be 32-bit, got 64-bit")
	}
	if table.Version != 1 {
		t.Errorf("expected version 1, got %d", table.Version)
	}
	if table.TotalSize != 1024*1024 {
		t.Errorf("expected total size 1MB, got %d", table.TotalSize)
	}
	if table.Offset0 != 1000 {
		t.Errorf("expected Offset0 to be 1000, got %d", table.Offset0)
	}
}

func TestParseSetupLdr_64Bit_Success(t *testing.T) {
	filePath := createMockInnoExe(t, true, false, false)
	defer os.Remove(filePath)

	table, err := ParseSetupLdr(filePath)
	if err != nil {
		t.Fatalf("expected successful parse, got error: %v", err)
	}

	if !table.Is64Bit {
		t.Error("expected table format to be 64-bit, got 32-bit")
	}
	if table.Version != 2 {
		t.Errorf("expected version 2, got %d", table.Version)
	}
	if table.TotalSize != 1024*1024*5 {
		t.Errorf("expected total size 5MB, got %d", table.TotalSize)
	}
	if table.OffsetEXE != 1000 {
		t.Errorf("expected OffsetEXE to be 1000, got %d", table.OffsetEXE)
	}
}

func TestParseSetupLdr_CorruptCRC_Failure(t *testing.T) {
	filePath := createMockInnoExe(t, false, true, false)
	defer os.Remove(filePath)

	_, err := ParseSetupLdr(filePath)
	if err == nil {
		t.Error("expected failure due to corrupt CRC, but got success")
	}
}

func TestParseSetupLdr_CorruptMagic_Failure(t *testing.T) {
	filePath := createMockInnoExe(t, false, false, true)
	defer os.Remove(filePath)

	_, err := ParseSetupLdr(filePath)
	if err == nil {
		t.Error("expected failure due to corrupt ExeHeader Magic, but got success")
	}
}

// Helper to create a temporary mock legacy Inno Setup file (pre-4.0.10)
func createMockInnoExeLegacy(t *testing.T, corruptMagic bool) string {
	tmpFile, err := os.CreateTemp("", "mock_inno_legacy_*.exe")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// 1. Padding up to ExeHeaderOffset (0x30)
	padding := make([]byte, SetupLdrExeHeaderOffset)
	if _, err := tmpFile.Write(padding); err != nil {
		t.Fatalf("failed to write padding: %v", err)
	}

	// 2. Write ExeHeader
	tableOffset := int32(512)
	exeHeader := SetupLdrExeHeader{
		ID:                   SetupLdrExeHeaderID,
		OffsetTableOffset:    tableOffset,
		NotOffsetTableOffset: ^tableOffset,
	}
	if corruptMagic {
		exeHeader.ID = 0x11223344
	}

	if err := binary.Write(tmpFile, binary.LittleEndian, &exeHeader); err != nil {
		t.Fatalf("failed to write exe header: %v", err)
	}

	// 3. Seek to tableOffset and write legacy table
	if _, err := tmpFile.Seek(int64(tableOffset), io.SeekStart); err != nil {
		t.Fatalf("failed to seek: %v", err)
	}

	var id [12]byte
	copy(id[:], offsetTableIDLegacy)

	tbl := SetupLdrOffsetTableLegacy{
		ID:                  id,
		TotalSize:           1024 * 500, // 500KB
		OffsetEXE:           100,
		CompressedSizeEXE:   50,
		UncompressedSizeEXE: 200,
		AdlerEXE:            0x55aa,
		OffsetMsg:           0,
		Offset0:             1000,
		Offset1:             2000,
	}

	if err := binary.Write(tmpFile, binary.LittleEndian, &tbl); err != nil {
		t.Fatalf("failed to write legacy table: %v", err)
	}

	return tmpFile.Name()
}

func TestParseSetupLdr_Legacy_Success(t *testing.T) {
	filePath := createMockInnoExeLegacy(t, false)
	defer os.Remove(filePath)

	table, err := ParseSetupLdr(filePath)
	if err != nil {
		t.Fatalf("expected successful parse of legacy table, got error: %v", err)
	}

	if table.Is64Bit {
		t.Error("expected table format to be 32-bit legacy, got 64-bit")
	}
	if table.Version != 0 {
		t.Errorf("expected legacy version 0, got %d", table.Version)
	}
	if table.TotalSize != 1024*500 {
		t.Errorf("expected total size 500KB, got %d", table.TotalSize)
	}
	if table.OffsetEXE != 100 {
		t.Errorf("expected OffsetEXE to be 100, got %d", table.OffsetEXE)
	}
	if table.Offset0 != 1000 {
		t.Errorf("expected Offset0 to be 1000, got %d", table.Offset0)
	}
	if table.Offset1 != 2000 {
		t.Errorf("expected Offset1 to be 2000, got %d", table.Offset1)
	}
}

