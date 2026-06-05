package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"innounp-go/parser"
)

// DefaultCommonPasswords holds standard installer and malware-analysis default keys.
var DefaultCommonPasswords = []string{
	"password", "123456", "12345", "1234", "admin", "setup", "install",
	"secret", "private", "pass", "123", "Inno", "InnoSetup", "setup123",
	"malware", "infected", "cracked", "crack", "key", "license",
	"infected123", "password123", "admin123", "setup.exe", "12345678",
}

func main() {
	listOnly := flag.Bool("l", false, "List files inside the installer without extracting them")
	outputDir := flag.String("o", "", "Destination directory for extraction (created if it doesn't exist)")
	password := flag.String("p", "", "Explicit decryption password if the installer is encrypted")
	crack := flag.Bool("crack", false, "Attempt parallel password recovery using a built-in common list")
	wordlistFile := flag.String("w", "", "Attempt parallel dictionary attack using passwords from a wordlist file")
	decompile := flag.Bool("d", false, "Decompile Pascal Script CompiledCode.bin from installer or standalone file")
	debug := flag.Bool("debug", false, "Enable verbose forensics and parsing debug logs")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <path_to_inno_setup_exe_or_bytecode>\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	filePath := flag.Arg(0)

	// --- Native Bytecode Decompiler Auto-Detection Loop ---
	if *decompile {
		var output string
		var err error

		if isStandaloneBytecode(filePath) {
			fmt.Printf("Analyzing Standalone Pascal Script Bytecode Payload: %s\n", filePath)
			fmt.Println("================================================================================")
			output, err = parser.DecompileIFPSFile(filePath)
		} else {
			fmt.Printf("Extracting and Disassembling Bytecode from Inno Setup Exe: %s\n", filePath)
			fmt.Println("================================================================================")
			output, err = parser.DecompileInnoExe(filePath)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Decompilation failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(output)
		return
	}

	// Set the global debug flag inside the parser package
	parser.EnableDebugLogging = *debug

	fmt.Printf("Analyzing Inno Setup Executable: %s\n", filePath)
	fmt.Println("================================================================================")

	// 1. Resolve offset tables and check validity
	table, err := parser.ParseSetupLdr(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing offset tables: %v\n", err)
		os.Exit(1)
	}

	if parser.EnableDebugLogging {
		fmt.Printf("Loader Offset Table verified successfully!\n\n")
		fmt.Printf("Offset Table Magic ID: %s\n", hex.EncodeToString(table.ID[:]))
		fmt.Printf("Table Format:          %s\n", map[bool]string{true: "64-bit", false: "32-bit"}[table.Is64Bit])
		fmt.Printf("Table Version:         %d\n", table.Version)
		fmt.Printf("Total EXE Size:        %d bytes\n", table.TotalSize)
		fmt.Printf("Offset EXE Block:      %d (0x%X)\n", table.OffsetEXE, table.OffsetEXE)
		fmt.Printf("Uncompressed EXE Size: %d bytes\n", table.UncompressedSizeEXE)
		fmt.Printf("CRC of EXE Block:      0x%X\n", uint32(table.CRCEXE))
		fmt.Printf("Offset0 (SETUP.0):     %d (0x%X)\n", table.Offset0, table.Offset0)
		fmt.Printf("Offset1 (SETUP-1.bin): %d (0x%X)\n", table.Offset1, table.Offset1)
		fmt.Println("================================================================================")

		// Read and print raw signature
		if fTest, err := os.Open(filePath); err == nil {
			fTest.Seek(table.Offset0, 0)
			sigBytes := make([]byte, 64)
			fTest.Read(sigBytes)
			fmt.Printf("[DEBUG] Raw Signature String: %q\n", string(sigBytes))
			fTest.Close()
		}
	}

	// 2. Parse file lists and locations
	ver, isUnicode, files, locations, crypt64, _, _, err := parser.ListFilesAndLocations(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing installer block: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Detected Inno Setup Installer Version: %d (Format: %s)\n", ver, map[bool]string{true: "Unicode", false: "Ansi"}[isUnicode])
	fmt.Printf("Number of File Payloads:               %d\n", len(files))
	fmt.Printf("Number of Locations:                   %d\n", len(locations))
	fmt.Println("================================================================================")

	// 3. Coordinate Multi-Threaded Password Recovery (Forensics / Sandbox Cracker)
	pass := *password
	if *crack || *wordlistFile != "" {
		fmt.Println("Initiating Multi-Core Parallel Password Recovery...")
		var list []string
		if *wordlistFile != "" {
			var err error
			list, err = readWordlist(*wordlistFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading wordlist: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Loaded %d words from dictionary: %s\n", len(list), *wordlistFile)
		} else {
			list = DefaultCommonPasswords
			fmt.Printf("Using built-in quick dictionary of %d forensic keys\n", len(list))
		}

		res, err := parser.CrackPassword(filePath, list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Password recovery error: %v\n", err)
			os.Exit(1)
		}

		if res.PasswordFound {
			fmt.Printf("\n[+] PASSWORD RECOVERED SUCCESSFULLY!\n")
			fmt.Printf("    Password:  %s\n", res.Password)
			fmt.Printf("    Hash Type: %s\n", res.HashType)
			fmt.Printf("    Guesses:   %d\n\n", res.TotalGuesses)
			pass = res.Password
		} else {
			fmt.Printf("\n[-] Password recovery failed: checked %d passwords but found no match\n", res.TotalGuesses)
			if *password == "" {
				fmt.Println("    Proceeding without password (encrypted payloads will fail)...")
			}
			fmt.Println()
		}
		fmt.Println("================================================================================")
	}

	if *listOnly {
		// --- List-Only Mode ---
		fmt.Printf("%-4s  %-12s  %-64s  %s\n", "ID", "Size (bytes)", "SHA1/SHA256 Hash (Metadata Catalog)", "Destination Path")
		fmt.Println("--------------------------------------------------------------------------------------------------------------------------------")
		for _, f := range files {
			hashStr := f.ExpectedHash
			if hashStr == "" {
				hashStr = "--------------------------------"
			}
			fmt.Printf("%-4d  %-12d  %-64s  %s\n", f.ID, f.OriginalSize, hashStr, f.DestName)
		}
		
		// Forensic Check: display unmapped location entries
		if len(locations) > len(files) {
			fmt.Println("\n[!] FORENSIC ALERT: Evasion Tactic Detected!")
			fmt.Printf("    Installer has %d file entries but %d location entries.\n", len(files), len(locations))
			fmt.Printf("    These unmapped locations typically hold hidden malware payloads!\n\n")
			fmt.Printf("%-4s  %-12s  %-10s  %-10s  %s\n", "ID", "Size (bytes)", "Compressed", "Encrypted", "Forensic Mock Path")
			fmt.Println("--------------------------------------------------------------------------------")
			for i, loc := range locations {
				// Check if this location is unmapped
				mapped := false
				for _, f := range files {
					if f.ID == i {
						mapped = true
						break
					}
				}
				if !mapped {
					isCompressed := hasFlag(loc.Flags, 7)
					isEncrypted := hasFlag(loc.Flags, 6)
					if parser.EnableDebugLogging {
						fmt.Printf("\n[DEBUG] Location ID %d Fields Dump:\n", i)
						fmt.Printf("    FirstSlice:          %d\n", loc.FirstSlice)
						fmt.Printf("    LastSlice:           %d\n", loc.LastSlice)
						fmt.Printf("    StartOffset:         %d (0x%X)\n", loc.StartOffset, loc.StartOffset)
						fmt.Printf("    ChunkSuboffset:      %d (0x%X)\n", loc.ChunkSuboffset, loc.ChunkSuboffset)
						fmt.Printf("    OriginalSize:        %d (0x%X)\n", loc.OriginalSize, loc.OriginalSize)
						fmt.Printf("    ChunkCompressedSize: %d (0x%X)\n", loc.ChunkCompressedSize, loc.ChunkCompressedSize)
						fmt.Printf("    SHA1Sum (hex):       %s\n", hex.EncodeToString(loc.SHA1Sum))
						fmt.Printf("    Flags (binary):      %b (0x%X)\n\n", loc.Flags, loc.Flags)
					}
					fmt.Printf("%-4d  %-12d  %-10t  %-10t  %s\n", i, loc.OriginalSize, isCompressed, isEncrypted, fmt.Sprintf("forensics/hidden_payload_%d.bin", i))
				}
			}
		}
		fmt.Println("================================================================================")
		return
	}

	// --- Extraction Mode ---
	destDir := *outputDir
	if destDir == "" {
		// Default to "./extracted_<exe_name>"
		baseName := filepath.Base(filePath)
		ext := filepath.Ext(baseName)
		destDir = "extracted_" + baseName[:len(baseName)-len(ext)]
	}

	fmt.Printf("Extracting payloads to: %s\n", destDir)
	fmt.Println("--------------------------------------------------------------------------------")

	var successCount, failCount int
	var totalBytesExtracted int64

	// Create output folder if it doesn't exist
	if err := os.MkdirAll(destDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	for _, f := range files {
		if f.DestName == "" {
			// Skip dummy/empty sync records
			continue
		}
		cleanDest := cleanInnoPath(f.DestName)
		destPath := filepath.Join(destDir, cleanDest)

		locIndex := f.LocationEntry
		if locIndex < 0 || locIndex >= len(locations) {
			fmt.Printf("Skipping file ID %d (no mapped location entry)\n", f.ID)
			failCount++
			continue
		}
		loc := locations[locIndex]

		// Format dynamic console prefix
		actionPrefix := "Extracting"
		if f.Encrypted {
			actionPrefix = "Decrypting & Extracting"
		}

		fmt.Printf("%-25s %-40s ... ", actionPrefix, truncateFilename(f.DestName, 38))

		// Set default compression method: Inno Setup 5.3.9+ (ver >= 5300) default-uses LZMA2 decompression!
		method := parser.CompressLZMA
		if ver >= 5300 {
			method = parser.CompressLZMA2
		}

		extractErr := parser.ExtractFile(filePath, table, ver, isUnicode, &loc, destPath, method, pass, crypt64)
		if extractErr != nil {
			fmt.Printf("FAILED (%v)\n", extractErr)
			failCount++
		} else {
			fmt.Println("OK")
			successCount++
			totalBytesExtracted += f.OriginalSize
		}
	}

	// Forensic Recovery Loop: Extract hidden unmapped payload locations directly (Defeating Evasion Tactics)
	if len(locations) > len(files) {
		fmt.Printf("\n[!] FORENSIC ACTION: Recovering %d hidden unmapped payload locations...\n", len(locations)-len(files))
		for i, loc := range locations {
			mapped := false
			for _, f := range files {
				if f.ID == i {
					mapped = true
					break
				}
			}
			if !mapped {
				destPath := filepath.Join(destDir, fmt.Sprintf("forensics/hidden_payload_%d.bin", i))
				fmt.Printf("Recovering Hidden Payload:   %-40s ... ", truncateFilename(fmt.Sprintf("forensics/hidden_payload_%d.bin", i), 38))

				method := parser.CompressLZMA
				if ver >= 5300 {
					method = parser.CompressLZMA2
				}

				extractErr := parser.ExtractFile(filePath, table, ver, isUnicode, &loc, destPath, method, pass, crypt64)
				if extractErr != nil {
					fmt.Printf("FAILED (%v)\n", extractErr)
					failCount++
				} else {
					fmt.Println("OK")
					successCount++
					if stat, err := os.Stat(destPath); err == nil {
						totalBytesExtracted += stat.Size()
					}
				}
			}
		}
	}

	// Print beautiful high-signal summary
	fmt.Println("================================================================================")
	fmt.Println("EXTRACTION COMPLETED SUMMARY:")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("Total Files Processed:     %d\n", len(files))
	fmt.Printf("Successfully Extracted:    %d\n", successCount)
	fmt.Printf("Failed to Extract:         %d\n", failCount)
	fmt.Printf("Total Bytes Decompressed:  %d bytes\n", totalBytesExtracted)
	fmt.Printf("Destination Directory:     %s\n", destDir)
	if pass != "" {
		fmt.Printf("Used Password:             %s\n", pass)
	}
	fmt.Println("================================================================================")
}

// isStandaloneBytecode checks if a file starts with the "IFPS" bytecode magic bytes.
func isStandaloneBytecode(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	var magic [4]byte
	n, err := file.Read(magic[:])
	if err != nil || n < 4 {
		return false
	}
	return string(magic[:]) == "IFPS"
}

// readWordlist loads dictionary words line-by-line using a memory-buffered scanner.
func readWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text != "" {
			words = append(words, text)
		}
	}
	return words, scanner.Err()
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

// truncateFilename ensures the filename fits neatly inside the console table columns.
func truncateFilename(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	return "..." + name[len(name)-maxLen+3:]
}

// hasFlag checks if a bit flag is set inside a bitset.
func hasFlag(flags uint32, bit uint) bool {
	return (flags & (1 << bit)) != 0
}
