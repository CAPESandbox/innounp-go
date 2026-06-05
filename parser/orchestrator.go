package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"innounp-go/parser/ifps"
)

// FileMetadata represents the metadata of a single file in the installer, returned as JSON.
type FileMetadata struct {
	ID             int    `json:"id"`
	SourceFilename string `json:"source_filename"`
	DestName       string `json:"dest_name"`
	OriginalSize   int64  `json:"original_size"`
	Compressed     bool   `json:"compressed"`
	Encrypted      bool   `json:"encrypted"`
}

// DetectVersionFromSetup0 reads the 64-byte signature at Offset0 and parses the version.
func DetectVersionFromSetup0(file *os.File, offset0 int64) (int, bool, error) {
	if _, err := file.Seek(offset0, io.SeekStart); err != nil {
		return 0, false, fmt.Errorf("failed to seek to Offset0: %w", err)
	}

	testID := make([]byte, 64)
	if _, err := io.ReadFull(file, testID); err != nil {
		return 0, false, fmt.Errorf("failed to read TestID signature: %w", err)
	}

	sig := string(testID)
	// Match Inno Setup Setup Data (X.Y.Z) or My Inno Setup Extensions...
	re := regexp.MustCompile(`(?:Inno Setup Setup Data|My Inno Setup Extensions Setup Data) \((\d)\.(\d)\.(\d+)\)`)
	matches := re.FindStringSubmatch(sig)
	if len(matches) < 4 {
		return 0, false, fmt.Errorf("invalid or unrecognized installer signature: %q", sig)
	}

	ver1, _ := strconv.Atoi(matches[1])
	ver2, _ := strconv.Atoi(matches[2])
	ver3, _ := strconv.Atoi(matches[3])

	ver := ver1*1000 + ver2*100 + ver3

	// Default fallback for modern versions if minor matches are missing
	if ver < 3000 {
		return 0, false, fmt.Errorf("installer version %d is too old or unsupported", ver)
	}

	// Detect Unicode flag (u)
	isUnicode := false
	if ver >= 6300 {
		isUnicode = true
	} else {
		unicodeRe := regexp.MustCompile(`\(u\)` + `|` + `\(U\)`)
		isUnicode = unicodeRe.MatchString(sig)
	}

	return ver, isUnicode, nil
}

// ListFilesAndLocations parses SETUP.0 and returns the unified list of file metadata and locations.
func ListFilesAndLocations(exePath string) (int, []FileMetadata, []UnifiedFileLocationEntry, *Is64EncryptionData, error) {
	file, err := os.Open(exePath)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to open executable: %w", err)
	}
	defer file.Close()

	// 1. Parse PE Offset Table
	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to parse PE Offset Table: %w", err)
	}

	// 2. Read signature string and detect version
	ver, _, err := DetectVersionFromSetup0(file, table.Offset0)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to detect Inno version: %w", err)
	}

	// 3. Read compressed block header for SETUP.0 at Offset0 + 64 bytes
	if _, err := file.Seek(table.Offset0+64, io.SeekStart); err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to seek to block header: %w", err)
	}

	blockHeader, err := ReadBlockHeader(file, ver)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to read SETUP.0 block header: %w", err)
	}

	// 4. Wrap file in decompressed block reader
	// SETUP.0 is zlib compressed for version <= 4105, and LZMA compressed for newer versions.
	compMethod := getSetup0CompressionMethod(ver)
	blockReader, err := NewBlockReader(file, blockHeader, compMethod)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to initialize block reader: %w", err)
	}
	defer blockReader.Close()

	// 5. Parse TSetupHeader
	headerSchema, ok := GetRecordSchema(ver, "TSetupHeader")
	if !ok {
		return 0, nil, nil, nil, errors.New("failed to retrieve schema for TSetupHeader")
	}

	parsedHeader, err := ReadRecord(blockReader, headerSchema)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("failed to parse SETUP header: %w", err)
	}

	// Extract counts of records safely (v1 doesn't have languages, types, etc.)
	numLanguages := getIntField(parsedHeader.Fields, "NumLanguageEntries")
	numMessages := getIntField(parsedHeader.Fields, "NumCustomMessageEntries")
	numPermissions := getIntField(parsedHeader.Fields, "NumPermissionEntries")
	numTypes := getIntField(parsedHeader.Fields, "NumTypeEntries")
	numComponents := getIntField(parsedHeader.Fields, "NumComponentEntries")
	numTasks := getIntField(parsedHeader.Fields, "NumTaskEntries")
	numDirs := getIntField(parsedHeader.Fields, "NumDirEntries")
	numFiles := getIntField(parsedHeader.Fields, "NumFileEntries")
	numLocations := getIntField(parsedHeader.Fields, "NumFileLocationEntries")

	// Extract encryption configuration (if v6+)
	var crypt64 *Is64EncryptionData
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

	// 6. Skip intermediate records sequentially
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

	for _, list := range skipList {
		schema, ok := GetRecordSchema(ver, list.schema)
		if !ok {
			return 0, nil, nil, nil, fmt.Errorf("failed to retrieve schema for %s", list.schema)
		}
		for i := uint32(0); i < list.count; i++ {
			if _, err := ReadRecord(blockReader, schema); err != nil {
				return 0, nil, nil, nil, fmt.Errorf("failed to skip list %s at item %d: %w", list.schema, i, err)
			}
		}
	}

	// 7. Parse File Entries
	fileSchema, ok := GetRecordSchema(ver, "TSetupFileEntry")
	if !ok {
		return 0, nil, nil, nil, errors.New("failed to retrieve schema for TSetupFileEntry")
	}

	filesMetadata := make([]FileMetadata, 0, numFiles)
	locationIndices := make([]int32, 0, numFiles)

	for i := uint32(0); i < numFiles; i++ {
		rec, err := ReadRecord(blockReader, fileSchema)
		if err != nil {
			return 0, nil, nil, nil, fmt.Errorf("failed to read file record %d: %w", i, err)
		}

		// Strings in TSetupFileEntry:
		// SourceFilename, DestName, InstallFontName, StrongAssemblyName, ...
		sourceFilename := ""
		destName := ""
		if len(rec.WideStrings) > 1 {
			sourceFilename = rec.WideStrings[0]
			destName = rec.WideStrings[1]
		}

		locationEntry := int32(rec.Fields["LocationEntry"].(uint32))
		externalSize := rec.Fields["ExternalSize"].(int64)

		filesMetadata = append(filesMetadata, FileMetadata{
			ID:             int(i),
			SourceFilename: sourceFilename,
			DestName:       destName,
			OriginalSize:   externalSize,
		})
		locationIndices = append(locationIndices, locationEntry)
	}

	// 8. Parse File Location Entries
	locSchema, ok := GetRecordSchema(ver, "TSetupFileLocationEntry")
	if !ok {
		return 0, nil, nil, nil, errors.New("failed to retrieve schema for TSetupFileLocationEntry")
	}

	locations := make([]UnifiedFileLocationEntry, 0, numLocations)
	for i := uint32(0); i < numLocations; i++ {
		rec, err := ReadRecord(blockReader, locSchema)
		if err != nil {
			return 0, nil, nil, nil, fmt.Errorf("failed to read file location %d: %w", i, err)
		}

		firstSlice := int32(rec.Fields["FirstSlice"].(uint32))
		lastSlice := int32(rec.Fields["LastSlice"].(uint32))
		startOffset := int32(rec.Fields["StartOffset"].(uint32))
		chunkSuboffset := rec.Fields["ChunkSuboffset"].(int64)
		originalSize := rec.Fields["OriginalSize"].(int64)
		chunkCompressedSize := rec.Fields["ChunkCompressedSize"].(int64)
		sha1Sum := rec.Fields["SHA1Sum"].([]byte)
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

	return ver, filesMetadata, locations, crypt64, nil
}

// ExtractAllFiles extracts every file from the installer executable.
func ExtractAllFiles(exePath string, outDir string, password string) error {
	ver, files, locations, crypt64, err := ListFilesAndLocations(exePath)
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
		// For simplicity, we match the location index to file metadata ID
		locIndex := f.ID
		if locIndex >= len(locations) {
			continue
		}
		loc := locations[locIndex]

		fmt.Printf("Extracting: %s -> %s\n", f.DestName, destPath)
		// Setup compression method: usually standard LZMA/LZMA2 for v5/v6 setups
		err := ExtractFile(exePath, table, ver, &loc, destPath, CompressLZMA, password, crypt64)
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
	_, files, _, _, err := ListFilesAndLocations(exePath)
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
		return val.(uint32)
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

	ver, _, err := DetectVersionFromSetup0(file, table.Offset0)
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

	headerSchema, _ := GetRecordSchema(ver, "TSetupHeader")
	parsedHeader, err := ReadRecord(blockReader, headerSchema)
	if err != nil {
		return "", err
	}

	if len(parsedHeader.AnsiStrings) < 4 {
		return "", errors.New("unsupported header structure: missing CompiledCode block")
	}

	compiledCodeBytes := []byte(parsedHeader.AnsiStrings[3])
	if len(compiledCodeBytes) == 0 {
		return "", errors.New("this Inno Setup installer does not contain custom Pascal Script compiled bytecode")
	}

	// Load bytecode into parser
	ifpsFile, err := ifps.ParseIFPS(bytes.NewReader(compiledCodeBytes))
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

	ifpsFile, err := ifps.ParseIFPS(file)
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
