package parser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// FileMetadata represents extracted details about an installer payload file.
type FileMetadata struct {
	ID             int    `json:"id"`
	SourceFilename string `json:"source_filename"`
	DestName       string `json:"dest_name"`
	OriginalSize   int64  `json:"original_size"`
	Compressed     bool   `json:"compressed"`
	Encrypted      bool   `json:"encrypted"`
	LocationEntry  int    `json:"location_entry"` // Mapped location entry index!
	ExpectedHash   string `json:"expected_hash"`   // Hex-encoded SHA1/SHA256 hash from catalog database!
}

// Is64EncryptionData holds PBKDF2 iterations, salt, and base nonce for modern v6 decryption.
type Is64EncryptionData struct {
	PasswordTest  int32
	KDFSalt       []byte
	KDFIterations int
	BaseNonce     []byte
}

// UnifiedFileLocationEntry holds metadata about a payload stream slice.
type UnifiedFileLocationEntry struct {
	FirstSlice          int32
	LastSlice           int32
	StartOffset         int64
	ChunkSuboffset      int64
	OriginalSize        int64
	ChunkCompressedSize int64
	SHA1Sum             []byte
	Flags               uint32
}

// hasFlag checks if a specific bit flag is set inside a bitset integer.
func hasFlag(flags uint32, bit uint) bool {
	return (flags & (1 << bit)) != 0
}

// DetectVersionFromSetup0 reads the 64-byte signature string at offset0 and extracts:
// 1. The parsed Inno Setup version integer (e.g. 5.5.0 -> 5500, 5.3.6 -> 5306).
// 2. A boolean indicating if the installer is Unicode (true) or ANSI (false).
func DetectVersionFromSetup0(r io.ReadSeeker, offset0 int64) (int, bool, error) {
	if _, err := r.Seek(offset0, io.SeekStart); err != nil {
		return 0, false, fmt.Errorf("failed to seek to signature offset %d: %w", offset0, err)
	}

	sigBytes := make([]byte, 64)
	if _, err := io.ReadFull(r, sigBytes); err != nil {
		return 0, false, fmt.Errorf("failed to read signature block: %w", err)
	}

	sig := string(sigBytes)
	// Typical formats:
	// "Inno Setup Setup Data (5.5.0)" -> ANSI (isUnicode = false)
	// "Inno Setup Setup Data (5.5.0) (u)" -> Unicode (isUnicode = true)
	prefix := "Inno Setup Setup Data ("
	if len(sig) < len(prefix) {
		return 0, false, errors.New("invalid signature block: too short")
	}

	// Verify prefix
	for i := 0; i < len(prefix); i++ {
		if sig[i] != prefix[i] {
			return 0, false, fmt.Errorf("invalid setup signature magic: %q", sig[:22])
		}
	}

	// Find the closing paren of the version
	verStr := ""
	endIdx := -1
	for i := len(prefix); i < len(sig); i++ {
		if sig[i] == ')' {
			verStr = sig[len(prefix):i]
			endIdx = i
			break
		}
	}

	if verStr == "" || endIdx == -1 {
		return 0, false, errors.New("failed to parse version from setup signature")
	}

	// Determine if Unicode (has " (u" after version paren)
	isUnicode := false
	if endIdx+4 <= len(sig) && sig[endIdx:endIdx+4] == ") (u" {
		isUnicode = true
	}

	// Parse version string (e.g. "5.5.0" -> 5500, "5.3.6" -> 5306)
	var major, minor, rev int
	n, _ := fmt.Sscanf(verStr, "%d.%d.%d", &major, &minor, &rev)
	if n < 2 {
		return 0, false, fmt.Errorf("failed to decode version string: %q", verStr)
	}

	ver := major*1000 + minor*100 + rev

	// Inno Setup 6.0.0+ discontinued the ANSI edition, meaning all installers
	// of version 6.x (ver >= 6000) are strictly and globally Unicode!
	if ver >= 6000 {
		isUnicode = true
	}

	return ver, isUnicode, nil
}
