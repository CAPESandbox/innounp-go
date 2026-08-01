package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"innounp-go/parser/ifps"
)

// LogProgress is called to print extraction progress and warnings. By default, it prints to standard output.
// Library consumers can disable or redirect progress logging by overriding or setting this to nil.
var LogProgress = func(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func logProgress(format string, a ...interface{}) {
	if LogProgress != nil {
		LogProgress(format, a...)
	}
}

// ListFilesAndLocations parses SETUP.0 and extracts file/location lists sequentially.
func ListFilesAndLocations(exePath string) (int, bool, []FileMetadata, []UnifiedFileLocationEntry, *Is64EncryptionData, []byte, []byte, SetupCompressMethod, error) {
	file, err := os.Open(exePath)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to open executable: %w", err)
	}
	defer file.Close()

	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to parse PE Offset Table: %w", err)
	}

	ver, isUnicode, err := DetectVersionFromSetup0(file, table.Offset0)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to detect Inno Setup version: %w", err)
	}

	var crypt64 *Is64EncryptionData
	setup0BlockOffset := table.Offset0 + 64

	if ver >= 6500 {
		// Seek to table.Offset0 + 64 (signature size is 64)
		if _, err := file.Seek(table.Offset0+64, io.SeekStart); err != nil {
			return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to seek to encryption header: %w", err)
		}

		var encHeaderCRC uint32
		if err := binary.Read(file, binary.LittleEndian, &encHeaderCRC); err != nil {
			return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to read encryption header CRC: %w", err)
		}

		var encHeader struct {
			EncryptionUse uint8
			KDFSalt       [16]byte
			KDFIterations uint32
			BaseNonce     [24]byte
			PasswordTest  int32
		}
		if err := binary.Read(file, binary.LittleEndian, &encHeader); err != nil {
			return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to read encryption header: %w", err)
		}

		// Verify CRC of the encryption header bytes
		var encBuf bytes.Buffer
		binary.Write(&encBuf, binary.LittleEndian, &encHeader)
		actualCRC := binary.LittleEndian.Uint32([]byte{0, 0, 0, 0}) // Just a dummy, let's compute real CRC!
		_ = actualCRC
		// Real CRC calculation via hash/crc32
		actualCRC = crc32.ChecksumIEEE(encBuf.Bytes())
		if actualCRC != encHeaderCRC {
			return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("encryption header CRC mismatch (expected %08x, got %08x)", encHeaderCRC, actualCRC)
		}

		crypt64 = &Is64EncryptionData{
			PasswordTest:  encHeader.PasswordTest,
			KDFSalt:       encHeader.KDFSalt[:],
			KDFIterations: int(encHeader.KDFIterations),
			BaseNonce:     encHeader.BaseNonce[:],
		}

		setup0BlockOffset += 4 + 49
	}

	// Read block header for SETUP.0 Block 1
	if _, err := file.Seek(setup0BlockOffset, io.SeekStart); err != nil {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to seek to SETUP.0 Block 1: %w", err)
	}

	blockHeader1, err := ReadBlockHeader(file, ver)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to read SETUP.0 Block 1 header: %w", err)
	}

	// Gracefully detect multi-disk spanned installers whose external setup-1.bin files are missing
	stat, statErr := file.Stat()
	if statErr == nil && int64(blockHeader1.StoredSize) > stat.Size() {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, errors.New("this file is only a small installer launcher (stub). The actual installation files and catalog database are stored in separate files (such as setup-1.bin) which are missing from this folder")
	}

	compMethod := getSetup0CompressionMethod(ver)
	var blockReader1 io.ReadCloser
	blockReader1, err = NewBlockReader(file, blockHeader1, compMethod, ver)
	
	// Self-healing metadata block 1 fallback: if classic LZMA fails, retry with LZMA2!
	var decompressedBuf1 bytes.Buffer
	if err == nil {
		_, err = io.Copy(&decompressedBuf1, blockReader1)
		if err != nil && EnableDebugLogging {
			fmt.Printf("[DEBUG] SETUP.0 block 1 decompression error: %v, buffer len: %d\n", err, decompressedBuf1.Len())
		}
		blockReader1.Close()
	}
	if err != nil {
		// Fallback to LZMA2
		decompressedBuf1.Reset()
		if _, seekErr := file.Seek(setup0BlockOffset, io.SeekStart); seekErr == nil {
			if blockHeader1Fallback, hdrErr := ReadBlockHeader(file, ver); hdrErr == nil {
				if blockReader1Fallback, decErr := NewBlockReader(file, blockHeader1Fallback, CompressLZMA2, ver); decErr == nil {
					if _, copyErr := io.Copy(&decompressedBuf1, blockReader1Fallback); copyErr == nil {
						err = nil
					}
					blockReader1Fallback.Close()
				}
			}
		}
	}
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, fmt.Errorf("failed to decompress SETUP.0 Block 1 metadata: %w", err)
	}
	rawBytes1 := decompressedBuf1.Bytes()
	r := bytes.NewReader(rawBytes1)

	// State variables extracted sequentially
	var parsedHeader *ParsedRecord
	var numLanguages, numMessages, numPermissions, numTypes, numComponents, numTasks, numDirs, numFiles, numLocations, numIcons, numInis, numRegs, numDeletes, numRuns uint32
	var filesMetadata []FileMetadata
	var locations []UnifiedFileLocationEntry
	var locationIndices []int32

	origVer := ver
	success := false
	returnedCompressMethod := compMethod

	// Multi-Attempt Self-Healing Try-Fallback Loop:
	// First attempt uses the detected version. If parsing fails, we automatically fallback to
	// modern, hybrid, or legacy layouts to heal spoofed installers.
	for attempt := 1; attempt <= 7; attempt++ {
		r.Seek(0, io.SeekStart)
		if attempt > 1 {
			if origVer == 5500 {
				if attempt == 2 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under spoofed 5.5.0 layout.\n")
					logProgress("    Self-healing to 7.0.x modern fallback...\n")
					ver = 7000
				} else if attempt == 3 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under spoofed 7.0.x layout.\n")
					logProgress("    Self-healing to 6.4.x modern fallback...\n")
					ver = 6400
				} else if attempt == 4 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under spoofed layouts.\n")
					logProgress("    Self-healing to 6.0.x fallback...\n")
					ver = 6000
				} else if attempt == 5 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under spoofed layouts.\n")
					logProgress("    Self-healing to 5.5.1 hybrid fallback...\n")
					ver = 5501
				} else if attempt == 6 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under spoofed layouts.\n")
					logProgress("    Self-healing to 5.3.x alignment fallback...\n")
					ver = 5300
				} else {
					break
				}
			} else if origVer == 6000 {
				if attempt == 2 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under 6.0.0 layout.\n")
					logProgress("    Self-healing to 6.7.x modern fallback...\n")
					ver = 6700
				} else if attempt == 3 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under 6.7.0 layout.\n")
					logProgress("    Self-healing to 6.6.0 fallback...\n")
					ver = 6600
				} else if attempt == 4 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under 6.6.0 layout.\n")
					logProgress("    Self-healing to 6.1.0 fallback...\n")
					ver = 6100
				} else if attempt == 5 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under 6.1.0 layout.\n")
					logProgress("    Self-healing to 5.5.0 fallback...\n")
					ver = 5500
				} else if attempt == 6 {
					logProgress("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under 5.5.0 layout.\n")
					logProgress("    Self-healing to 5.3.0 fallback...\n")
					ver = 5300
				} else {
					break
				}
			} else {
				break
			}
		}

		headerSchema, ok := GetRecordSchema(ver, "TSetupHeader", isUnicode)
		if !ok {
			debugPrintf("[DEBUG] Attempt %d: failed to retrieve schema for TSetupHeader\n", attempt)
			continue
		}

		if EnableDebugLogging {
			logProgress("[DEBUG-POS] Position before Header: %d\n", r.Size() - int64(r.Len()))
		}
		var err error
		parsedHeader, err = ReadRecord(r, headerSchema, isUnicode)
		if EnableDebugLogging {
			logProgress("[DEBUG-POS] Position after Header: %d\n", r.Size() - int64(r.Len()))
			pos := r.Size() - int64(r.Len())
			if pos+64 <= int64(len(rawBytes1)) {
				logProgress("[DEBUG-HEX] Next 64 bytes: %x\n", rawBytes1[pos:pos+64])
			} else {
				logProgress("[DEBUG-HEX] Next bytes: %x\n", rawBytes1[pos:])
			}
		}
		if err != nil {
			debugPrintf("[DEBUG] Attempt %d: failed to parse SETUP header: %v\n", attempt, err)
			continue
		}

		// Skip legacy custom bitmaps appended to the header for Inno Setup < 4.0.0
		if ver < 4000 {
			options := getInt64Field(parsedHeader.Fields, "Options")
			if (options & (1 << 2)) != 0 {
				if EnableDebugLogging {
					fmt.Println("[DEBUG] Legacy Wizard Image detected, skipping...")
				}
				var strLen uint32
				if err := binary.Read(r, binary.LittleEndian, &strLen); err != nil {
					debugPrintf("[DEBUG] Failed to read legacy WizardImage length: %v\n", err)
					continue
				}
				if strLen > 0 {
					if _, err := io.CopyN(io.Discard, r, int64(strLen)); err != nil {
						debugPrintf("[DEBUG] Failed to skip legacy WizardImage payload: %v\n", err)
						continue
					}
				}
			}
			if (options & (1 << 3)) != 0 {
				if EnableDebugLogging {
					fmt.Println("[DEBUG] Legacy Small Wizard Image detected, skipping...")
				}
				var strLen uint32
				if err := binary.Read(r, binary.LittleEndian, &strLen); err != nil {
					debugPrintf("[DEBUG] Failed to read legacy WizardSmallImage length: %v\n", err)
					continue
				}
				if strLen > 0 {
					if _, err := io.CopyN(io.Discard, r, int64(strLen)); err != nil {
						debugPrintf("[DEBUG] Failed to skip legacy WizardSmallImage payload: %v\n", err)
						continue
					}
				}
			}
		}

		if ver < 4000 && EnableDebugLogging {
			logProgress("[DEBUG-POS] Position after skipping legacy bitmaps: %d\n", r.Size() - int64(r.Len()))
			pos := r.Size() - int64(r.Len())
			if pos+64 <= int64(len(rawBytes1)) {
				logProgress("[DEBUG-HEX] Next 64 bytes after legacy bitmaps: %x\n", rawBytes1[pos:pos+64])
			} else {
				logProgress("[DEBUG-HEX] Next bytes after legacy bitmaps: %x\n", rawBytes1[pos:])
			}
		}

		if EnableDebugLogging {
			logProgress("[DEBUG] Header WideStrings (%d): %+v\n", len(parsedHeader.WideStrings), parsedHeader.WideStrings)
			logProgress("[DEBUG] Header AnsiStrings (%d): %+v\n", len(parsedHeader.AnsiStrings), parsedHeader.AnsiStrings)
			logProgress("[DEBUG] Header Fields: %+v\n", parsedHeader.Fields)
		}

		// Self-Healing Heuristic Check: Check if UninstallDisplaySize is astronomically huge (e.g. > 10 Terabytes)
		// which indicates an offset shift due to version spoofing (64-bit vs 32-bit UninstallDisplaySize).
		if displaySizeVal, ok := parsedHeader.Fields["UninstallDisplaySize"]; ok && attempt == 1 {
			var displaySize int64
			switch v := displaySizeVal.(type) {
			case int64:
				displaySize = v
			case uint32:
				displaySize = int64(v)
			case uint64:
				displaySize = int64(v)
			}
			if displaySize > 10995116277760 || displaySize < 0 {
				logProgress("\n[!] FORENSIC HEURISTIC: Detected Version Spoofing via large uninstall size (%d bytes)!\n", displaySize)
				logProgress("    Self-healing stream alignment in progress...\n")
				ver = 5205
				headerSchema, _ = GetRecordSchema(5205, "TSetupHeader", isUnicode)
				r.Seek(0, io.SeekStart)
				parsedHeader, err = ReadRecord(r, headerSchema, isUnicode)
				if err != nil {
					debugPrintf("[DEBUG] Attempt %d (Self-Healed): failed to re-parse setup header: %v\n", attempt, err)
					continue
				}
			}
		}

		// Extract counts of records safely
		numLanguages = getIntField(parsedHeader.Fields, "NumLanguageEntries")
		numMessages = getIntField(parsedHeader.Fields, "NumCustomMessageEntries")
		numPermissions = getIntField(parsedHeader.Fields, "NumPermissionEntries")
		numTypes = getIntField(parsedHeader.Fields, "NumTypeEntries")
		numComponents = getIntField(parsedHeader.Fields, "NumComponentEntries")
		numTasks = getIntField(parsedHeader.Fields, "NumTaskEntries")
		numDirs = getIntField(parsedHeader.Fields, "NumDirEntries")
		numFiles = getIntField(parsedHeader.Fields, "NumFileEntries")
		numLocations = getIntField(parsedHeader.Fields, "NumFileLocationEntries")
		numIcons = getIntField(parsedHeader.Fields, "NumIconEntries")
		numInis = getIntField(parsedHeader.Fields, "NumIniEntries")
		numRegs = getIntField(parsedHeader.Fields, "NumRegistryEntries")
		numDeletes = getIntField(parsedHeader.Fields, "NumInstallDeleteEntries") + getIntField(parsedHeader.Fields, "NumUninstallDeleteEntries")
		numRuns = getIntField(parsedHeader.Fields, "NumRunEntries") + getIntField(parsedHeader.Fields, "NumUninstallRunEntries")

		if EnableDebugLogging {
			fmt.Printf("[DEBUG-COUNTS] ver=%d numLanguages=%d, numMessages=%d, numDirs=%d, numFiles=%d, numLocations=%d, numIcons=%d\n", ver, numLanguages, numMessages, numDirs, numFiles, numLocations, numIcons)
			fmt.Printf("[DEBUG-FIELDS] Fields: %+v\n", parsedHeader.Fields)
			pos := r.Size() - int64(r.Len())
			endHex := pos + 64
			if endHex > int64(len(rawBytes1)) {
				endHex = int64(len(rawBytes1))
			}
			fmt.Printf("[DEBUG-POS-HEX] Next 64 bytes at start of lists (pos=%d): %x\n", pos, rawBytes1[pos:endHex])
			// Print language fixed fields starting at position 148348
			if len(rawBytes1) >= 148348+64 {
				fmt.Printf("[DEBUG-LANG-FIXED-HEX] Next 64 bytes of language fixed fields (pos=148348): %x\n", rawBytes1[148348:148348+64])
			}
		}

		// Extract encryption configuration (if v6+)
		if ver < 6500 {
			crypt64 = nil
			if ver >= 6400 {
				if passTestVal, ok := parsedHeader.Fields["PasswordTest"]; ok {
					crypt64 = &Is64EncryptionData{
						PasswordTest:  int32(passTestVal.(uint32)),
						KDFSalt:       parsedHeader.Fields["EncryptionKDFSalt"].([]byte),
						KDFIterations: int(parsedHeader.Fields["EncryptionKDFIterations"].(uint32)),
						BaseNonce:     parsedHeader.Fields["EncryptionBaseNonce"].([]byte),
					}
				}
			}
		}

		// Skip intermediate records sequentially
		skipList := []struct {
			schema string
			count  uint32
		}{
			{"TSetupLanguageEntry", numLanguages},
			{"TSetupCustomMessageEntry", numMessages},
			{"TSetupPermissionEntry", numPermissions},
			{"TSetupTypeEntry", numTypes},
			{"TSetupComponentEntry", numComponents},
			{"TSetupTaskEntry", numTasks},
			{"TSetupDirEntry", numDirs},
		}

		skipFailed := false
		for _, list := range skipList {
			schema, ok := GetRecordSchema(ver, list.schema, isUnicode)
			if !ok {
				debugPrintf("[DEBUG] Attempt %d: failed to retrieve schema for %s\n", attempt, list.schema)
				skipFailed = true
				break
			}
			for i := uint32(0); i < list.count; i++ {
				if EnableDebugLogging {
					logProgress("[DEBUG-POS] Position before skipping %s item %d: %d\n", list.schema, i, r.Size() - int64(r.Len()))
				}
				if EnableDebugLogging && list.schema == "TSetupLanguageEntry" {
					posBefore := r.Size() - int64(r.Len())
					fmt.Printf("[DEBUG-LANG-HEX] Bytes before TSetupLanguageEntry item %d: %x\n", i, rawBytes1[posBefore:posBefore+128])
				}
				if _, err := ReadRecord(r, schema, isUnicode); err != nil {
					debugPrintf("[DEBUG] Attempt %d: failed to skip list %s at item %d: %v\n", attempt, list.schema, i, err)
					skipFailed = true
					break
				}
			}
			if skipFailed {
				break
			}
		}
		if skipFailed {
			continue
		}

		// Parse File Entries
		fileSchema, ok := GetRecordSchema(ver, "TSetupFileEntry", isUnicode)
		if !ok {
			debugPrintf("[DEBUG] Attempt %d: failed to retrieve schema for TSetupFileEntry\n", attempt)
			continue
		}

		filesMetadata = make([]FileMetadata, 0, numFiles)
		locationIndices = make([]int32, 0, numFiles)
		fileFailed := false

		for i := uint32(0); i < numFiles; i++ {
			rec, err := ReadRecord(r, fileSchema, isUnicode)
			if err != nil {
				debugPrintf("[DEBUG] Attempt %d: failed to read file record %d: %v\n", attempt, i, err)
				fileFailed = true
				break
			}

			sourceFilename := ""
			destName := ""
			if len(rec.WideStrings) > 1 {
				sourceFilename = rec.WideStrings[0]
				destName = rec.WideStrings[1]
			} else if len(rec.AnsiStrings) > 1 {
				sourceFilename = rec.AnsiStrings[0]
				destName = rec.AnsiStrings[1]
			}

			locationEntry := int32(getIntField(rec.Fields, "LocationEntry"))
			if ver < 4000 {
				locationEntry = int32(i)
			}
			externalSize := getInt64Field(rec.Fields, "ExternalSize")

			filesMetadata = append(filesMetadata, FileMetadata{
				ID:             int(i),
				SourceFilename: sourceFilename,
				DestName:       destName,
				OriginalSize:   externalSize,
				LocationEntry:  int(locationEntry),
			})
			locationIndices = append(locationIndices, locationEntry)
		}
		if fileFailed {
			continue
		}

		// Skip trailing table entries sequentially written between Files and Locations:
		// 1. TSetupIconEntry
		// 2. TSetupIniEntry
		// 3. TSetupRegistryEntry
		// 4. TSetupDeleteEntry
		// 5. TSetupRunEntry
		skipPostList := []struct {
			schema string
			count  uint32
		}{
			{"TSetupIconEntry", numIcons},
			{"TSetupIniEntry", numInis},
			{"TSetupRegistryEntry", numRegs},
			{"TSetupDeleteEntry", numDeletes},
			{"TSetupRunEntry", numRuns},
		}

		postFailed := false
		for _, list := range skipPostList {
			schema, ok := GetRecordSchema(ver, list.schema, isUnicode)
			if !ok {
				debugPrintf("[DEBUG] Attempt %d: failed to retrieve post-schema for %s\n", attempt, list.schema)
				postFailed = true
				break
			}
			for i := uint32(0); i < list.count; i++ {
				if _, err := ReadRecord(r, schema, isUnicode); err != nil {
					debugPrintf("[DEBUG] Attempt %d: failed to skip post-list %s at item %d: %v\n", attempt, list.schema, i, err)
					postFailed = true
					break
				}
			}
			if postFailed {
				break
			}
		}
		if postFailed {
			continue
		}

		// Skip Wizard Images and Compressor DLL sequential stubs at the end of Block 1
		if ver >= 4000 {
			if err := skipImageList(r); err != nil {
				debugPrintf("[DEBUG] Attempt %d: failed to skip Wizard Images: %v\n", attempt, err)
				continue
			}
			if ver >= 2001 {
				if err := skipImageList(r); err != nil {
					debugPrintf("[DEBUG] Attempt %d: failed to skip Small Wizard Images: %v\n", attempt, err)
					continue
				}
			}
			compressMethod := getIntField(parsedHeader.Fields, "CompressMethod")
			returnedCompressMethod = SetupCompressMethod(compressMethod)
			if err := skipDecompDll(r, ver, uint8(compressMethod)); err != nil {
				debugPrintf("[DEBUG] Attempt %d: failed to skip Decompressor DLL: %v\n", attempt, err)
				continue
			}
		}

		// Seek to raw EXE Block 2 (Locations Block) containing TSetupFileLocationEntry records.
		// Block 2 starts exactly after Block 1's compressed data (signature size + block header + compressed size).
		// If there is no separate Block 2 (such as in mock tests), we read from Block 1 directly.
		headerSize := int64(9)
		if ver < 3000 {
			headerSize = 16
		} else if ver >= 6700 {
			headerSize = 13
		}
		block2Offset := setup0BlockOffset + headerSize + int64(blockHeader1.StoredSize)

		var locReader io.Reader = r
		var fileSize int64 = 0
		if stat, err := file.Stat(); err == nil {
			fileSize = stat.Size()
		}

		if block2Offset < fileSize {
			if _, err := file.Seek(block2Offset, io.SeekStart); err == nil {
				blockHeader2, err := ReadBlockHeader(file, ver)
				if err == nil {
					blockReader2, err := NewBlockReader(file, blockHeader2, compMethod, ver)
					if err == nil {
						var decompressedBuf2 bytes.Buffer
						if _, err := io.Copy(&decompressedBuf2, blockReader2); err == nil {
							locReader = bytes.NewReader(decompressedBuf2.Bytes())
						}
						blockReader2.Close()
					}
				}
			}
		}

		// Parse File Location Entries from locReader
		locSchema, ok := GetRecordSchema(ver, "TSetupFileLocationEntry", isUnicode)
		if !ok {
			debugPrintf("[DEBUG] Attempt %d: failed to retrieve schema for TSetupFileLocationEntry\n", attempt)
			continue
		}

		locations = make([]UnifiedFileLocationEntry, 0, numLocations)
		locFailed := false
		for i := uint32(0); i < numLocations; i++ {
			rec, err := ReadRecord(locReader, locSchema, isUnicode)
			if err != nil {
				debugPrintf("[DEBUG] Attempt %d: failed to read file location %d: %v\n", attempt, i, err)
				locFailed = true
				break
			}

			if EnableDebugLogging && i < 5 {
				logProgress("[DEBUG-LOC] Location %d: %+v\n", i, rec.Fields)
			}

			firstSlice := int32(rec.Fields["FirstSlice"].(uint32))
			lastSlice := int32(rec.Fields["LastSlice"].(uint32))
			
			var startOffset int64
			if sVal, exists := rec.Fields["StartOffset"]; exists {
				switch v := sVal.(type) {
				case uint32:
					startOffset = int64(v)
				case int64:
					startOffset = v
				}
			}

			chunkSuboffset := getInt64Field(rec.Fields, "ChunkSuboffset")
			originalSize := getInt64Field(rec.Fields, "OriginalSize")
			chunkCompressedSize := getInt64Field(rec.Fields, "ChunkCompressedSize")
			
			// Safely support either SHA1Sum or SHA256Sum based on compiler version
			var sha1Sum []byte
			if hVal, exists := rec.Fields["SHA256Sum"]; exists {
				sha1Sum = hVal.([]byte)
			} else if hVal, exists := rec.Fields["SHA1Sum"]; exists {
				sha1Sum = hVal.([]byte)
			}
			
			flags := rec.Fields["Flags"].(uint32)

			locations = append(locations, UnifiedFileLocationEntry{
				FirstSlice:          firstSlice,
				LastSlice:           lastSlice,
				StartOffset:         startOffset,
				ChunkSuboffset:      chunkSuboffset,
				OriginalSize:        originalSize,
				ChunkCompressedSize: chunkCompressedSize,
				SHA1Sum:             sha1Sum,
				Flags:               flags,
			})
		}
		if locFailed {
			continue
		}

		// Update metadata sizes with actual uncompressed sizes from location blocks
		for i := range filesMetadata {
			locEntry := locationIndices[i]
			if locEntry >= 0 && int(locEntry) < len(locations) {
				loc := locations[locEntry]
				filesMetadata[i].OriginalSize = loc.OriginalSize
				filesMetadata[i].Compressed = hasFlag(loc.Flags, 7) // foChunkCompressed is bit 7
				filesMetadata[i].Encrypted = hasFlag(loc.Flags, 6)  // foChunkEncrypted is bit 6
				if len(loc.SHA1Sum) > 0 {
					filesMetadata[i].ExpectedHash = hex.EncodeToString(loc.SHA1Sum)
				} else {
					filesMetadata[i].ExpectedHash = ""
				}
			}
		}

		// Parsing completed successfully!
		success = true
		break
	}

	if !success {
		return 0, false, nil, nil, nil, nil, nil, CompressLZMA, errors.New("failed to parse Inno Setup catalog after all try-fallback attempts")
	}

	// Extract password fields for cracking propagation
	var passwordHash []byte
	var passwordSalt []byte
	if hashField, ok := parsedHeader.Fields["PasswordHash"]; ok {
		passwordHash = hashField.([]byte)
	}
	if saltField, ok := parsedHeader.Fields["PasswordSalt"]; ok {
		passwordSalt = saltField.([]byte)
	}

	// Print final metadata counts summary
	debugPrintf("\n[DEBUG] Parsing Completed Successfully! Extracted Record Counts:\n")
	debugPrintf("    Languages:      %d\n", numLanguages)
	debugPrintf("    Messages:       %d\n", numMessages)
	debugPrintf("    Dirs:           %d\n", numDirs)
	debugPrintf("    Files:          %d\n", numFiles)
	debugPrintf("    Locations:      %d\n", numLocations)
	debugPrintf("    Runs:           %d\n\n", numRuns)

	return ver, isUnicode, filesMetadata, locations, crypt64, passwordHash, passwordSalt, returnedCompressMethod, nil
}

// ExtractAllFiles extracts every file from the installer executable.
func ExtractAllFiles(exePath string, outDir string, password string) (int, int, int64, error) {
	ver, isUnicode, files, locations, crypt64, _, _, compMethod, err := ListFilesAndLocations(exePath)
	if err != nil {
		return 0, 0, 0, err
	}

	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return 0, 0, 0, err
	}

	var successCount, failCount int
	var totalBytesExtracted int64

	// 1. Group files by their location chunk (StartOffset + ChunkCompressedSize)
	type ChunkKey struct {
		StartOffset int32
		Size        int64
	}

	type FileWithLoc struct {
		File *FileMetadata
		Loc  *UnifiedFileLocationEntry
	}

	chunkGroups := make(map[ChunkKey][]FileWithLoc)
	for i := range files {
		f := &files[i]
		locIndex := f.LocationEntry
		if locIndex < 0 || locIndex >= len(locations) {
			continue
		}
		loc := &locations[locIndex]
		key := ChunkKey{int32(loc.StartOffset), loc.ChunkCompressedSize}
		chunkGroups[key] = append(chunkGroups[key], FileWithLoc{f, loc})
	}

	// Open the executable file once outside the loop
	file, err := os.Open(exePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to open executable: %w", err)
	}
	defer file.Close()

	// 2. Process each unique chunk sequentially
	for key, group := range chunkGroups {
		// Sort files in the chunk by ChunkSuboffset
		sort.Slice(group, func(i, j int) bool {
			return group[i].Loc.ChunkSuboffset < group[j].Loc.ChunkSuboffset
		})

		// Seek to chunk start offset
		absOffset := table.Offset1 + int64(key.StartOffset)
		if _, err := file.Seek(absOffset, io.SeekStart); err != nil {
			return 0, 0, 0, fmt.Errorf("failed to seek to chunk start: %w", err)
		}

		// Read and verify comp ID: 'zlb'#26, 'lzm'#26, 'lz2'#26 (high byte is 0x1A)
		var compID uint32
		if err := binary.Read(file, binary.LittleEndian, &compID); err != nil {
			return 0, 0, 0, fmt.Errorf("failed to read comp ID: %w", err)
		}
		if (compID >> 24) != 0x1A {
			return 0, 0, 0, fmt.Errorf("invalid compression ID: source block is corrupted (compID read: 0x%08X)", compID)
		}

		// Setup Decryption Reader
		var rawReader io.Reader = file
		firstLoc := group[0].Loc
		if hasFlag(firstLoc.Flags, 6) { // foChunkEncrypted
			if password == "" {
				return 0, 0, 0, errors.New("file is encrypted but no password was specified")
			}
			if ver < 6400 {
				salt := make([]byte, 8)
				if _, err := io.ReadFull(file, salt); err != nil {
					return 0, 0, 0, fmt.Errorf("failed to read encryption salt: %w", err)
				}
				cipher, err := InitializeRC4Decryptor(password, salt, true, isUnicode)
				if err != nil {
					return 0, 0, 0, fmt.Errorf("failed to initialize RC4 decryptor: %w", err)
				}
				rawReader = &DecryptReader{underlying: file, cipherRC4: cipher}
			} else {
				if crypt64 == nil {
					return 0, 0, 0, errors.New("missing v6 encryption configuration")
				}
				keyBytes := GenerateChaCha20Key(password, crypt64.KDFSalt, crypt64.KDFIterations)
				nonce := RecreateChaCha20Nonce(crypt64.BaseNonce, int64(key.StartOffset), firstLoc.FirstSlice)
				cipher, err := InitializeChaCha20Decryptor(keyBytes, nonce)
				if err != nil {
					return 0, 0, 0, fmt.Errorf("failed to initialize ChaCha20 decryptor: %w", err)
				}
				rawReader = &DecryptReader{underlying: file, cipherCC20: cipher}
			}
		}

		// Determine the compression method for this chunk based on chunk flags
		chunkCompMethod := compMethod
		if !hasFlag(firstLoc.Flags, 7) { // foChunkCompressed is bit 7
			chunkCompMethod = CompressStored
		}

		// Initialize Decompressor Stream
		decompressor, err := NewDecompressor(rawReader, chunkCompMethod)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("failed to initialize decompressor: %w", err)
		}

		// Process files sequentially in single-pass
		var currentStreamPos int64 = 0
		for _, item := range group {
			cleanDest := cleanInnoPath(item.File.DestName)
			destPath := filepath.Join(outDir, cleanDest)

			// Normalize filename display
			logProgress("Extracting: %-50s ... ", truncateFilename(item.File.DestName, 48))

			// Discard bytes to reach the ChunkSuboffset
			diff := item.Loc.ChunkSuboffset - currentStreamPos
			if diff > 0 {
				if _, err := io.CopyN(io.Discard, decompressor, diff); err != nil {
					logProgress("FAILED (failed to skip %d bytes: %v)\n", diff, err)
					failCount++
					continue
				}
				currentStreamPos += diff
			} else if diff < 0 {
				logProgress("FAILED (stream misalignment: current pos %d, target suboffset %d)\n", currentStreamPos, item.Loc.ChunkSuboffset)
				failCount++
				continue
			}

			// Extract file
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				logProgress("FAILED (failed to create dir: %v)\n", err)
				failCount++
				continue
			}

			destFile, err := os.Create(destPath)
			if err != nil {
				logProgress("FAILED (failed to create file: %v)\n", err)
				failCount++
				continue
			}

			// Use defensive size capped buffer reading
			buf := make([]byte, 64*1024)
			bytesLeft := item.Loc.OriginalSize
			fileFailed := false
			for bytesLeft > 0 {
				toRead := int64(len(buf))
				if toRead > bytesLeft {
					toRead = bytesLeft
				}
				n, rerr := io.ReadFull(decompressor, buf[:toRead])
				if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
					logProgress("FAILED (read error: %v)\n", rerr)
					fileFailed = true
					break
				}
				if n == 0 {
					break
				}
				if _, werr := destFile.Write(buf[:n]); werr != nil {
					logProgress("FAILED (write error: %v)\n", werr)
					fileFailed = true
					break
				}
				bytesLeft -= int64(n)
				currentStreamPos += int64(n)
			}
			destFile.Close()

			if !fileFailed {
				logProgress("OK\n")
				successCount++
				totalBytesExtracted += item.File.OriginalSize
			} else {
				failCount++
			}
		}

		decompressor.Close()
	}

	return successCount, failCount, totalBytesExtracted, nil
}

// cleanInnoPath replaces custom Inno path constants like "{app}" with standard folders.
func cleanInnoPath(innoPath string) string {
	importPath := innoPath
	if len(importPath) > 0 && importPath[0] == '{' {
		endIdx := -1
		for i, char := range importPath {
			if char == '}' {
				endIdx = i
				break
			}
		}
		if endIdx != -1 {
			importPath = importPath[endIdx+1:]
		}
	}
	// Normalize backslashes to forward slashes on macOS/Linux
	importPath = strings.ReplaceAll(importPath, "\\", "/")
	return filepath.Clean(importPath)
}

// ListFilesJSON returns the list of files in the installer as a JSON string.
func ListFilesJSON(exePath string) (string, error) {
	_, _, files, _, _, _, _, _, err := ListFilesAndLocations(exePath)
	if err != nil {
		return "", err
	}

	jsonBytes, err := json.Marshal(files)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// getIntField safely reads a uint32 value from a parsed record field map, defaulting to 0 if missing.
func getIntField(fields map[string]interface{}, name string) uint32 {
	if val, ok := fields[name]; ok {
		switch v := val.(type) {
		case uint32:
			return v
		case uint16:
			return uint32(v)
		case uint8:
			return uint32(v)
		case int32:
			return uint32(v)
		case int16:
			return uint32(v)
		case int8:
			return uint32(v)
		case int:
			return uint32(v)
		case int64:
			return uint32(v)
		case uint64:
			return uint32(v)
		}
	}
	return 0
}

// getInt64Field safely reads an int64 value from a parsed record field map, defaulting to 0 if missing.
func getInt64Field(fields map[string]interface{}, name string) int64 {
	if val, ok := fields[name]; ok {
		switch v := val.(type) {
		case int64:
			return v
		case uint32:
			return int64(v)
		case uint64:
			return int64(v)
		case int32:
			return int64(v)
		case int:
			return int64(v)
		}
	}
	return 0
}

// DecompileInnoExe extracts and decompiles compiled Pascal script bytecode from the Inno Setup executable.
func DecompileInnoExe(exePath string) (string, error) {
	file, err := os.Open(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to open executable: %w", err)
	}
	defer file.Close()

	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse PE Offset Table: %w", err)
	}

	ver, isUnicode, err := DetectVersionFromSetup0(file, table.Offset0)
	if err != nil {
		return "", fmt.Errorf("failed to detect Inno version: %w", err)
	}

	setup0BlockOffset := table.Offset0 + 64
	if ver >= 6500 {
		setup0BlockOffset += 4 + 49
	}

	// Read block header for SETUP.0
	if _, err := file.Seek(setup0BlockOffset, io.SeekStart); err != nil {
		return "", err
	}
	blockHeader, err := ReadBlockHeader(file, ver)
	if err != nil {
		return "", err
	}

	compMethod := getSetup0CompressionMethod(ver)
	blockReader, err := NewBlockReader(file, blockHeader, compMethod, ver)
	if err != nil {
		return "", err
	}
	defer blockReader.Close()

	var decompressedBuf bytes.Buffer
	if _, err := io.Copy(&decompressedBuf, blockReader); err != nil {
		return "", fmt.Errorf("failed to decompress SETUP.0 block: %w", err)
	}
	rawBytes := decompressedBuf.Bytes()
	r := bytes.NewReader(rawBytes)

	headerSchema, _ := GetRecordSchema(ver, "TSetupHeader", isUnicode)
	parsedHeader, err := ReadRecord(r, headerSchema, isUnicode)
	if err != nil {
		return "", err
	}

	// Dynamic bytecode offset: CompiledCodeText is always the final AnsiString
	codeIndex := len(parsedHeader.AnsiStrings) - 1

	if codeIndex < 0 {
		return "", errors.New("unsupported header structure: missing CompiledCode block")
	}

	compiledCodeBytes := []byte(parsedHeader.AnsiStrings[codeIndex])
	if len(compiledCodeBytes) == 0 {
		return "", errors.New("this Inno Setup installer does not contain custom Pascal Script compiled bytecode")
	}

	// Load bytecode into parser
	ifpsFile, err := ifps.ParseIFPS(bytes.NewReader(compiledCodeBytes), isUnicode)
	if err != nil {
		return "", fmt.Errorf("failed to parse IFPS bytecode structure: %w", err)
	}

	return ifps.Disassemble(ifpsFile)
}

// DecompileIFPSFile reads and decompiles a standalone CompiledCode.bin file directly.
func DecompileIFPSFile(ifpsPath string) (string, error) {
	file, err := os.Open(ifpsPath)
	if err != nil {
		return "", fmt.Errorf("failed to open bytecode file: %w", err)
	}
	defer file.Close()

	ifpsFile, err := ifps.ParseIFPS(file, false) // standalone .bin default to ANSI
	if err != nil {
		return "", fmt.Errorf("failed to parse IFPS bytecode structure: %w", err)
	}

	return ifps.Disassemble(ifpsFile)
}

// getSetup0CompressionMethod maps the SETUP.0 metadata block's compression format.
func getSetup0CompressionMethod(ver int) SetupCompressMethod {
	if ver == 9999 || ver == 5909 {
		return CompressZip
	}
	if ver <= 4105 {
		return CompressZip
	}
	return CompressLZMA
}

// skipImageList reads and discards an image list sequential stub from the decompressed metadata stream.
func skipImageList(r io.Reader) error {
	var count int32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil
		}
		return err
	}
	if count < 20 { // standard image list count is small
		for i := 0; i < int(count); i++ {
			var length int32
			if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return nil
				}
				return err
			}
			if length > 0 {
				if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
					return err
				}
			}
		}
	} else {
		// Single image with already read length count
		if count > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(count)); err != nil {
				return err
			}
		}
	}
	return nil
}

// skipDecompDll reads and discards the compressor DLL sequential stub from the decompressed metadata stream.
func skipDecompDll(r io.Reader, ver int, compressMethod uint8) error {
	// bzip, LZMA v4.1.05, and Zip v4.2.06+ have decompressor DLL written sequentially
	if compressMethod == 1 || (compressMethod == 2 && ver == 4105) || (compressMethod == 0 && ver >= 4206) {
		var length int32
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if length > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
				return err
			}
		}
	}
	return nil
}

// truncateFilename ensures the filename fits neatly inside the console table columns.
func truncateFilename(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	return "..." + name[len(name)-maxLen+3:]
}
