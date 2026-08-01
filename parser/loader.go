package parser

import (
	"bytes"
	"debug/pe"
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

func isValidOffset0(filePath string, offset0 int64) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	ver, _, err := DetectVersionFromSetup0(file, offset0)
	if err != nil {
		return false
	}

	// If version >= 4.0.0, we MUST also verify that there is a mathematically valid block header at offset0 + 64!
	if ver >= 4000 {
		if _, err := file.Seek(offset0+64, io.SeekStart); err != nil {
			return false
		}

		var crcExpected uint32
		if err := binary.Read(file, binary.LittleEndian, &crcExpected); err != nil {
			return false
		}

		headerSize := 5
		if ver >= 6700 {
			headerSize = 9
		}
		headerBytes := make([]byte, headerSize)
		if _, err := io.ReadFull(file, headerBytes); err != nil {
			return false
		}

		actualCRC := crc32.ChecksumIEEE(headerBytes)
		if actualCRC != crcExpected {
			return false
		}
	}

	return true
}

// ParseSetupLdr opens an Inno Setup EXE, parses its PE headers to locate the
// SetupLdrOffsetTable, and extracts verified offset information.
// It features an automatic dual-path fallback:
// 1. Tries to read the ExeHeader directly from the DOS stub at offset 0x30.
// 2. If missing, it traverses the PE .rsrc tree to extract resource 11111.
func ParseSetupLdr(filePath string) (*UnifiedOffsetTable, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var backupTable *UnifiedOffsetTable

	// --- Path 1: Traverse PE .rsrc Tree for Resource 11111 (Most authoritative for modern loaders) ---
	table, err := tryParsePEResources(filePath)
	if err == nil {
		if isValidOffset0(filePath, table.Offset0) {
			if table.Offset1 > 0 {
				return table, nil
			}
			// Decoupled payload discovery: if Offset1 is 0, let's see if tryParseSignatureScan can find it!
			if sigTable, scanErr := tryParseSignatureScan(filePath); scanErr == nil {
				return sigTable, nil
			}
			return table, nil
		}
		backupTable = table
	}

	// --- Path 2: Try DOS Stub ExeHeader at offset 0x30 (For older legacy loaders) ---
	table, err = tryParseDOSStubHeader(file)
	if err == nil {
		if isValidOffset0(filePath, table.Offset0) {
			if table.Offset1 > 0 {
				return table, nil
			}
			if sigTable, scanErr := tryParseSignatureScan(filePath); scanErr == nil {
				return sigTable, nil
			}
			return table, nil
		}
		if backupTable == nil {
			backupTable = table
		}
	}

	// --- Path 3: Signature-Scanning Fallback (For highly custom-packed or protected loaders) ---
	table, scanErr := tryParseSignatureScan(filePath)
	if scanErr == nil {
		return table, nil
	}

	if backupTable != nil {
		return backupTable, nil
	}

	return nil, fmt.Errorf("invalid Inno Setup installer executable (failed both DOS-stub 0x30, PE resource 11111, and signature scans): %w", err)
}

func tryParseSignatureScan(filePath string) (*UnifiedOffsetTable, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	sig := []byte("Inno Setup Setup Data")
	offset := len(data)
	var validTables []*UnifiedOffsetTable

	for {
		idx := bytes.LastIndex(data[:offset], sig)
		if idx == -1 {
			break
		}

		if isValidOffset0(filePath, int64(idx)) {
			// Search SETUP-1.bin payload signature globally: 0x1A626C7A (zlb\x1a)
			payloadSig := []byte{0x7a, 0x6c, 0x62, 0x1a} // 0x1A626C7A in little-endian
			offset1 := bytes.Index(data, payloadSig)
			if offset1 == -1 {
				offset1 = 0
			}

			validTables = append(validTables, &UnifiedOffsetTable{
				Version:   1,
				TotalSize: int64(len(data)),
				Offset0:   int64(idx),
				Offset1:   int64(offset1),
				Is64Bit:   false,
			})
		}

		offset = idx
	}

	if len(validTables) > 0 {
		// Return the first valid occurrence in the file (index of real overlay), defeating decoy trails
		return validTables[len(validTables)-1], nil
	}

	return nil, errors.New("setup data signature not found or no valid overlay signature found")
}

func tryParseDOSStubHeader(file *os.File) (*UnifiedOffsetTable, error) {
	if _, err := file.Seek(SetupLdrExeHeaderOffset, io.SeekStart); err != nil {
		return nil, err
	}

	var exeHeader SetupLdrExeHeader
	if err := binary.Read(file, binary.LittleEndian, &exeHeader); err != nil {
		return nil, err
	}

	if exeHeader.ID != SetupLdrExeHeaderID {
		return nil, errors.New("missing Inno magic ID at offset 0x30")
	}
	if exeHeader.OffsetTableOffset != ^exeHeader.NotOffsetTableOffset {
		return nil, errors.New("offset table corruption check failed at offset 0x30")
	}

	offset := int64(exeHeader.OffsetTableOffset)
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	rawTable := make([]byte, 64)
	n, err := io.ReadFull(file, rawTable)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if n < 44 {
		return nil, fmt.Errorf("file truncated when reading offset table (read %d bytes)", n)
	}

	return parseRawOffsetTable(rawTable)
}

func tryParsePEResources(filePath string) (*UnifiedOffsetTable, error) {
	peFile, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE executable structure: %w", err)
	}
	defer peFile.Close()

	// 1. Locate the .rsrc section
	var rsrcSec *pe.Section
	for _, sec := range peFile.Sections {
		if sec.Name == ".rsrc" {
			rsrcSec = sec
			break
		}
	}
	if rsrcSec == nil {
		return nil, errors.New("PE binary does not contain a .rsrc section")
	}

	// 2. Read raw bytes of the .rsrc section
	rsrcBytes, err := rsrcSec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .rsrc section bytes: %w", err)
	}

	// 3. Traverse Resource Directory Tree to find Type 10 (RT_RCDATA), Name 11111 (SetupLdrOffsetTableResID)
	// Level 1: Types Directory Table (at offset 0)
	typeDirOffset, found := findResourceEntry(rsrcBytes, 0, 10, true)
	if !found {
		return nil, errors.New("missing Type 10 (RT_RCDATA) in .rsrc tree")
	}

	// Level 2: Names Directory Table
	nameDirOffset, found := findResourceEntry(rsrcBytes, typeDirOffset, 11111, true)
	if !found {
		return nil, errors.New("missing resource ID 11111 in Type 10 .rsrc sub-tree")
	}

	// Level 3: Languages Directory Table (Follow first default language leaf)
	langLeafOffset, found := findResourceFirstLanguageLeaf(rsrcBytes, nameDirOffset)
	if !found {
		return nil, errors.New("missing language leaf in resource 11111 sub-tree")
	}

	// Read Resource Data Entry
	if len(rsrcBytes) < int(langLeafOffset+16) {
		return nil, errors.New("resource tree data entry is truncated")
	}
	dataRVA := binary.LittleEndian.Uint32(rsrcBytes[langLeafOffset : langLeafOffset+4])
	size := binary.LittleEndian.Uint32(rsrcBytes[langLeafOffset+4 : langLeafOffset+8])

	// Translate DataRVA to raw file offset
	fileOffset := uint32(0)
	for _, sec := range peFile.Sections {
		if dataRVA >= sec.VirtualAddress && dataRVA < sec.VirtualAddress+sec.Size {
			fileOffset = sec.Offset + (dataRVA - sec.VirtualAddress)
			break
		}
	}
	if fileOffset == 0 {
		return nil, fmt.Errorf("failed to map resource RVA 0x%X to file offset", dataRVA)
	}

	// 4. Read the offset table bytes directly from file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Seek(int64(fileOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to resource payload at %d: %w", fileOffset, err)
	}

	rawTable := make([]byte, size)
	if _, err := io.ReadFull(file, rawTable); err != nil {
		return nil, fmt.Errorf("failed to read resource payload bytes: %w", err)
	}

	return parseRawOffsetTable(rawTable)
}

// findResourceEntry traverses a resource directory table and searches for a specific ID entry.
// Returns the nested offset and true if found.
func findResourceEntry(rsrcBytes []byte, offset uint32, targetID uint32, expectDir bool) (uint32, bool) {
	if len(rsrcBytes) < int(offset+16) {
		return 0, false
	}

	numNamed := binary.LittleEndian.Uint16(rsrcBytes[offset+12 : offset+14])
	numID := binary.LittleEndian.Uint16(rsrcBytes[offset+14 : offset+16])
	totalEntries := int(numNamed + numID)

	entriesStart := offset + 16
	if len(rsrcBytes) < int(entriesStart+uint32(totalEntries)*8) {
		return 0, false
	}

	for i := 0; i < totalEntries; i++ {
		entryOffset := entriesStart + uint32(i)*8
		nameOrID := binary.LittleEndian.Uint32(rsrcBytes[entryOffset : entryOffset+4])
		offsetToData := binary.LittleEndian.Uint32(rsrcBytes[entryOffset+4 : entryOffset+8])

		// High bit of nameOrID specifies named vs ID resource (0 = ID)
		isID := (nameOrID & 0x80000000) == 0

		if isID && nameOrID == targetID {
			// High bit of offsetToData specifies subdirectory vs data entry (1 = subdirectory)
			isDir := (offsetToData & 0x80000000) != 0
			nextOffset := offsetToData & 0x7FFFFFFF

			if expectDir == isDir {
				return nextOffset, true
			}
		}
	}

	return 0, false
}

// findResourceFirstLanguageLeaf follows the first language entry in a table, returning the leaf's data entry offset.
func findResourceFirstLanguageLeaf(rsrcBytes []byte, offset uint32) (uint32, bool) {
	if len(rsrcBytes) < int(offset+16) {
		return 0, false
	}

	numNamed := binary.LittleEndian.Uint16(rsrcBytes[offset+12 : offset+14])
	numID := binary.LittleEndian.Uint16(rsrcBytes[offset+14 : offset+16])
	if numNamed+numID == 0 {
		return 0, false
	}

	// Grab the very first entry (which usually corresponds to the default language)
	entryOffset := offset + 16
	offsetToData := binary.LittleEndian.Uint32(rsrcBytes[entryOffset+4 : entryOffset+8])

	// For a language leaf, offsetToData must point to a terminal leaf (high bit 0)
	isDir := (offsetToData & 0x80000000) != 0
	if isDir {
		return 0, false
	}

	return offsetToData, true
}

func parseRawOffsetTable(rawTable []byte) (*UnifiedOffsetTable, error) {
	if len(rawTable) < 12 {
		return nil, errors.New("offset table is truncated")
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

	// Decode Table and verify CRC
	if isLegacy {
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
