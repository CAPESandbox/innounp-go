package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"innounp-go/parser/ifps"
)

// ListFilesAndLocations parses SETUP.0 and extracts file/location lists sequentially.
func ListFilesAndLocations(exePath string) (int, bool, []FileMetadata, []UnifiedFileLocationEntry, *Is64EncryptionData, []byte, []byte, error) {
	file, err := os.Open(exePath)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, fmt.Errorf("failed to open executable: %w", err)
	}
	defer file.Close()

	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, fmt.Errorf("failed to parse PE Offset Table: %w", err)
	}

	ver, isUnicode, err := DetectVersionFromSetup0(file, table.Offset0)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, fmt.Errorf("failed to detect Inno Setup version: %w", err)
	}

	// Read block header for SETUP.0 Block 1
	if _, err := file.Seek(table.Offset0+64, io.SeekStart); err != nil {
		return 0, false, nil, nil, nil, nil, nil, fmt.Errorf("failed to seek to SETUP.0 Block 1: %w", err)
	}

	blockHeader1, err := ReadBlockHeader(file, ver)
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, fmt.Errorf("failed to read SETUP.0 Block 1 header: %w", err)
	}

	// Gracefully detect multi-disk spanned installers whose external setup-1.bin files are missing
	stat, statErr := file.Stat()
	if statErr == nil && int64(blockHeader1.StoredSize) > stat.Size() {
		return 0, false, nil, nil, nil, nil, nil, errors.New("this file is only a small installer launcher (stub). The actual installation files and catalog database are stored in separate files (such as setup-1.bin) which are missing from this folder")
	}

	compMethod := getSetup0CompressionMethod(ver)
	var blockReader1 io.ReadCloser
	blockReader1, err = NewBlockReader(file, blockHeader1, compMethod)
	
	// Self-healing metadata block 1 fallback: if classic LZMA fails, retry with LZMA2!
	var decompressedBuf1 bytes.Buffer
	if err == nil {
		_, err = io.Copy(&decompressedBuf1, blockReader1)
		blockReader1.Close()
	}
	if err != nil {
		// Fallback to LZMA2
		decompressedBuf1.Reset()
		if _, seekErr := file.Seek(table.Offset0+64, io.SeekStart); seekErr == nil {
			if blockHeader1Fallback, hdrErr := ReadBlockHeader(file, ver); hdrErr == nil {
				if blockReader1Fallback, decErr := NewBlockReader(file, blockHeader1Fallback, CompressLZMA2); decErr == nil {
					if _, copyErr := io.Copy(&decompressedBuf1, blockReader1Fallback); copyErr == nil {
						err = nil
					}
					blockReader1Fallback.Close()
				}
			}
		}
	}
	if err != nil {
		return 0, false, nil, nil, nil, nil, nil, fmt.Errorf("failed to decompress SETUP.0 Block 1 metadata: %w", err)
	}
	rawBytes1 := decompressedBuf1.Bytes()
	r := bytes.NewReader(rawBytes1)

	// State variables extracted sequentially
	var parsedHeader *ParsedRecord
	var numLanguages, numMessages, numPermissions, numTypes, numComponents, numTasks, numDirs, numFiles, numLocations, numIcons, numInis, numRegs, numDeletes, numRuns uint32
	var crypt64 *Is64EncryptionData
	var filesMetadata []FileMetadata
	var locations []UnifiedFileLocationEntry
	var locationIndices []int32

	origVer := ver
	success := false

	// Two-Attempt Self-Healing Try-Fallback Loop:
	// First attempt uses the detected version. If parsing fails, we automatically fallback to
	// version 5300 (Cardinal-aligned display size and MD5/SHA-1 password boundaries) to heal spoofed installers.
	for attempt := 1; attempt <= 2; attempt++ {
		r.Seek(0, io.SeekStart)
		if attempt == 2 {
			if origVer == 5500 {
				fmt.Printf("\n[!] FORENSIC HEURISTIC: Sequential parsing failed under spoofed 5.5.0 layout.\n")
				fmt.Println("    Self-healing to 5.3.x alignment fallback...")
				ver = 5300
			} else {
				break
			}
		}

		headerSchema, ok := GetRecordSchema(ver, "TSetupHeader", isUnicode)
		if !ok {
			debugPrintf("[DEBUG] Attempt %d: failed to retrieve schema for TSetupHeader\n", attempt)
			continue
		}

		var err error
		parsedHeader, err = ReadRecord(r, headerSchema, isUnicode)
		if err != nil {
			debugPrintf("[DEBUG] Attempt %d: failed to parse SETUP header: %v\n", attempt, err)
			continue
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
				fmt.Printf("\n[!] FORENSIC HEURISTIC: Detected Version Spoofing via large uninstall size (%d bytes)!\n", displaySize)
				fmt.Println("    Self-healing stream alignment in progress...")
				ver = 5300
				headerSchema, _ = GetRecordSchema(5300, "TSetupHeader", isUnicode)
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

		// Extract encryption configuration (if v6+)
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

			locationEntry := int32(rec.Fields["LocationEntry"].(uint32))
			externalSize := rec.Fields["ExternalSize"].(int64)

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
			if err := skipDecompDll(r, ver, uint8(compressMethod)); err != nil {
				debugPrintf("[DEBUG] Attempt %d: failed to skip Decompressor DLL: %v\n", attempt, err)
				continue
			}
		}

		// Seek to raw EXE Block 2 (Locations Block) containing TSetupFileLocationEntry records.
		// Block 2 starts exactly after Block 1's compressed data (signature size + block header + compressed size).
		// If there is no separate Block 2 (such as in mock tests), we read from Block 1 directly.
		block2Offset := table.Offset0 + 64 + 9 + int64(blockHeader1.StoredSize)

		var locReader io.Reader = r
		var fileSize int64 = 0
		if stat, err := file.Stat(); err == nil {
			fileSize = stat.Size()
		}

		if block2Offset < fileSize {
			if _, err := file.Seek(block2Offset, io.SeekStart); err == nil {
				blockHeader2, err := ReadBlockHeader(file, ver)
				if err == nil {
					blockReader2, err := NewBlockReader(file, blockHeader2, compMethod)
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

			firstSlice := int32(rec.Fields["FirstSlice"].(uint32))
			lastSlice := int32(rec.Fields["LastSlice"].(uint32))
			startOffset := int32(rec.Fields["StartOffset"].(uint32))
			chunkSuboffset := rec.Fields["ChunkSuboffset"].(int64)
			originalSize := rec.Fields["OriginalSize"].(int64)
			chunkCompressedSize := rec.Fields["ChunkCompressedSize"].(int64)
			
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
			}
		}

		// Parsing completed successfully!
		success = true
		break
	}

	if !success {
		return 0, false, nil, nil, nil, nil, nil, errors.New("failed to parse Inno Setup catalog after all try-fallback attempts")
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

	return ver, isUnicode, filesMetadata, locations, crypt64, passwordHash, passwordSalt, nil
}

// ExtractAllFiles extracts every file from the installer executable.
func ExtractAllFiles(exePath string, outDir string, password string) error {
	ver, isUnicode, files, locations, crypt64, _, _, err := ListFilesAndLocations(exePath)
	if err != nil {
		return err
	}

	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return err
	}

	for _, f := range files {
		// Determine local extraction path, mapping e.g. "{app}\bin\file.dll" -> "outDir/app/bin/file.dll"
		cleanDest := cleanInnoPath(f.DestName)
		destPath := filepath.Join(outDir, cleanDest)

		// Get the file location index
		locIndex := f.LocationEntry
		if locIndex < 0 || locIndex >= len(locations) {
			continue
		}
		loc := locations[locIndex]

		fmt.Printf("Extracting: %s -> %s\n", f.DestName, destPath)
		err := ExtractFile(exePath, table, ver, isUnicode, &loc, destPath, CompressLZMA, password, crypt64)
		if err != nil {
			fmt.Printf("Warning: Failed to extract %s: %v\n", f.DestName, err)
		}
	}

	return nil
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
	return filepath.Clean(importPath)
}

// ListFilesJSON returns the list of files in the installer as a JSON string.
func ListFilesJSON(exePath string) (string, error) {
	_, _, files, _, _, _, _, err := ListFilesAndLocations(exePath)
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

	// Read block header for SETUP.0
	if _, err := file.Seek(table.Offset0+64, io.SeekStart); err != nil {
		return "", err
	}
	blockHeader, err := ReadBlockHeader(file, ver)
	if err != nil {
		return "", err
	}

	compMethod := getSetup0CompressionMethod(ver)
	blockReader, err := NewBlockReader(file, blockHeader, compMethod)
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

	// Dynamic bytecode offset: Unicode has CompiledCodeText at index 3,
	// while ANSI stores CompiledCodeText at index 30!
	codeIndex := 30
	if isUnicode {
		codeIndex = 3
	}

	if len(parsedHeader.AnsiStrings) <= codeIndex {
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
