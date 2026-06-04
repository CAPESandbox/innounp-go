package parser

import (
	"encoding/hex"
)

// Constants defining loader offsets and signatures.
const (
	// SetupLdrExeHeaderOffset is the seek offset ($30) inside the setup executable to locate the ExeHeader.
	SetupLdrExeHeaderOffset = 0x30

	// SetupLdrExeHeaderID is the magic marker 'Inno' ($6F6E6E49) in little-endian.
	SetupLdrExeHeaderID = 0x6F6E6E49

	// SetupLdrOffsetTableIDHex is the hexadecimal representation of the 12-byte SetupLdrOffsetTableID:
	// 'rDlPtS' #$CD #$E6 #$D7 #$7B #$0B #$2A
	SetupLdrOffsetTableIDHex = "72446c507453cde6d77b0b2a"
)

// SetupLdrOffsetTableID holds the parsed byte signature of a valid offset table.
var SetupLdrOffsetTableID []byte

func init() {
	var err error
	SetupLdrOffsetTableID, err = hex.DecodeString(SetupLdrOffsetTableIDHex)
	if err != nil {
		panic(err)
	}
}

// SetupLdrExeHeader is written inside a SetupLdr-enabled setup.exe at offset $30.
type SetupLdrExeHeader struct {
	ID                   int32 // Must equal SetupLdrExeHeaderID
	OffsetTableOffset    int32 // Seek offset to the start of the Offset Table
	NotOffsetTableOffset int32 // Bitwise NOT of OffsetTableOffset (validation check)
}

// UnifiedOffsetTable is a unified representation of the Offset Table for downstream consumption.
type UnifiedOffsetTable struct {
	ID                  [12]byte
	Version             uint32
	TotalSize           int64
	OffsetEXE           int64
	UncompressedSizeEXE uint32
	CRCEXE              int32
	Offset0             int64
	Offset1             int64
	Is64Bit             bool
}

// SetupLdrOffsetTable32 is the 32-bit layout used by Inno Setup 5 and some older versions.
type SetupLdrOffsetTable32 struct {
	ID                  [12]byte
	Version             uint32
	TotalSize           uint32
	OffsetEXE           uint32
	UncompressedSizeEXE uint32
	CRCEXE              int32
	Offset0             uint32
	Offset1             uint32
	TableCRC            int32
}

// SetupLdrOffsetTable64 is the 64-bit layout used by Inno Setup 6.
type SetupLdrOffsetTable64 struct {
	ID                  [12]byte
	Version             uint32
	TotalSize           int64
	OffsetEXE           int64
	UncompressedSizeEXE uint32
	CRCEXE              int32
	Offset0             int64
	Offset1             int64
	ReservedPadding     uint32
	TableCRC            int32
}

// SetupLdrOffsetTableLegacy is the legacy layout used by Inno Setup 1.x through 4.0.9.
type SetupLdrOffsetTableLegacy struct {
	ID                  [12]byte
	TotalSize           uint32
	OffsetEXE           uint32
	CompressedSizeEXE   uint32
	UncompressedSizeEXE uint32
	AdlerEXE            int32
	OffsetMsg           uint32
	Offset0             uint32
	Offset1             uint32
}

