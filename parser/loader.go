package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// Define both modern (v4.0.10+) and legacy (v1.x - v4.0.9) offset table signatures.
const (
	SetupLdrOffsetTableID_ModernHex = "72446c507453cde6d77b0b2a" // 'rDlPtS'#$CD#$E6#$D7#$7B#$0B#$2A
	SetupLdrOffsetTableID_LegacyHex = "72446c507453303287655678" // 'rDlPtS02'#$87#$65#$56#$78
)

var (
	offsetTableIDModern []byte
	offsetTableIDLegacy []byte
)

func init() {
	var err error
	offsetTableIDModern, err = hex.DecodeString(SetupLdrOffsetTableID_ModernHex)
	if err != nil {
		panic(err)
	}
	offsetTableIDLegacy, err = hex.DecodeString(SetupLdrOffsetTableID_LegacyHex)
	if err != nil {
		panic(err)
	}
}

// ParseSetupLdr opens an Inno Setup EXE, parses its PE headers to locate the
// SetupLdrOffsetTable, and extracts verified offset information.
func ParseSetupLdr(filePath string) (*UnifiedOffsetTable, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// 1. Read SetupLdrExeHeader at offset 0x30
	if _, err := file.Seek(SetupLdrExeHeaderOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to ExeHeader: %w", err)
	}

	var exeHeader SetupLdrExeHeader
	if err := binary.Read(file, binary.LittleEndian, &exeHeader); err != nil {
		return nil, fmt.Errorf("failed to read ExeHeader: %w", err)
	}

	// 2. Validate ExeHeader
	if exeHeader.ID != SetupLdrExeHeaderID {
		return nil, errors.New("invalid installer executable: missing Inno magic ID")
	}
	if exeHeader.OffsetTableOffset != ^exeHeader.NotOffsetTableOffset {
		return nil, errors.New("invalid installer executable: offset table corruption check failed")
	}

	// 3. Seek to OffsetTableOffset and inspect table ID
	offset := int64(exeHeader.OffsetTableOffset)
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to offset table at %d: %w", offset, err)
	}

	// Read maximum potential offset table size (64 bytes for SetupLdrOffsetTable64)
	rawTable := make([]byte, 64)
	n, err := io.ReadFull(file, rawTable)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("failed to read offset table: %w", err)
	}
	if n < 44 {
		return nil, fmt.Errorf("failed to read offset table: file truncated (read %d bytes)", n)
	}

	tableID := rawTable[:12]
	var isLegacy bool

	if bytes.Equal(tableID, offsetTableIDModern) {
		isLegacy = false
	} else if bytes.Equal(tableID, offsetTableIDLegacy) {
		isLegacy = true
	} else {
		return nil, fmt.Errorf("unknown or unsupported offset table signature: %s", hex.EncodeToString(tableID))
	}

	// 4. Decode Table and verify CRC
	if isLegacy {
		// Legacy tables do not have CRC32. They are 32-bit only.
		return decodeLegacyTable(rawTable)
	}

	return decodeModernTable(rawTable)
}

func decodeLegacyTable(raw []byte) (*UnifiedOffsetTable, error) {
	var tbl SetupLdrOffsetTableLegacy
	r := bytes.NewReader(raw[:44])
	if err := binary.Read(r, binary.LittleEndian, &tbl); err != nil {
		return nil, fmt.Errorf("failed to read legacy offset table: %w", err)
	}

	return &UnifiedOffsetTable{
		ID:                  tbl.ID,
		Version:             0,
		TotalSize:           int64(tbl.TotalSize),
		OffsetEXE:           int64(tbl.OffsetEXE),
		UncompressedSizeEXE: tbl.UncompressedSizeEXE,
		CRCEXE:              tbl.AdlerEXE,
		Offset0:             int64(tbl.Offset0),
		Offset1:             int64(tbl.Offset1),
		Is64Bit:             false,
	}, nil
}

func decodeModernTable(raw []byte) (*UnifiedOffsetTable, error) {
	// A modern offset table can be 32-bit (44 bytes) or 64-bit (64 bytes).
	// We distinguish them by calculating the CRC32 checksums.

	// Attempt 32-bit decode (44 bytes total, CRC32 is over first 40 bytes)
	crc32_32bitExpected := binary.LittleEndian.Uint32(raw[40:44])
	actualCRC_32bit := crc32.ChecksumIEEE(raw[:40])

	if actualCRC_32bit == crc32_32bitExpected {
		// Valid 32-bit table!
		var tbl32 SetupLdrOffsetTable32
		r := bytes.NewReader(raw[:44])
		if err := binary.Read(r, binary.LittleEndian, &tbl32); err != nil {
			return nil, err
		}

		return &UnifiedOffsetTable{
			ID:                  tbl32.ID,
			Version:             tbl32.Version,
			TotalSize:           int64(tbl32.TotalSize),
			OffsetEXE:           int64(tbl32.OffsetEXE),
			UncompressedSizeEXE: tbl32.UncompressedSizeEXE,
			CRCEXE:              tbl32.CRCEXE,
			Offset0:             int64(tbl32.Offset0),
			Offset1:             int64(tbl32.Offset1),
			Is64Bit:             false,
		}, nil
	}

	// Attempt 64-bit decode (64 bytes total, CRC32 is over first 60 bytes)
	crc32_64bitExpected := binary.LittleEndian.Uint32(raw[60:64])
	actualCRC_64bit := crc32.ChecksumIEEE(raw[:60])

	if actualCRC_64bit == crc32_64bitExpected {
		// Valid 64-bit table!
		var tbl64 SetupLdrOffsetTable64
		r := bytes.NewReader(raw[:64])
		if err := binary.Read(r, binary.LittleEndian, &tbl64); err != nil {
			return nil, err
		}

		return &UnifiedOffsetTable{
			ID:                  tbl64.ID,
			Version:             tbl64.Version,
			TotalSize:           tbl64.TotalSize,
			OffsetEXE:           tbl64.OffsetEXE,
			UncompressedSizeEXE: tbl64.UncompressedSizeEXE,
			CRCEXE:              tbl64.CRCEXE,
			Offset0:             tbl64.Offset0,
			Offset1:             tbl64.Offset1,
			Is64Bit:             true,
		}, nil
	}

	return nil, errors.New("failed to validate offset table: CRC check failed for both 32-bit and 64-bit layouts")
}
