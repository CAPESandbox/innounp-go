package parser

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
)

// PasswordCrackResult contains statistics and results from a completed recovery run.
type PasswordCrackResult struct {
	PasswordFound bool
	Password      string
	HashType      string
	TotalGuesses  int64
}

// CrackPassword reads the setup header, automatically extracts password candidate strings
// from the compiled Pascal Script bytecode (if present), and runs a parallel dictionary attack.
func CrackPassword(exePath string, wordlist []string) (*PasswordCrackResult, error) {
	// 1. Retrieve the file schemas and parse counts
	ver, isUnicode, _, _, crypt64, expectedHash, salt, _, err := ListFilesAndLocations(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse installer blocks: %w", err)
	}

	if EnableDebugLogging {
		fmt.Printf("[DEBUG] Cracker Loaded Parameters: ver=%d, expectedHash=%s, salt=%s\n",
			ver, hex.EncodeToString(expectedHash), hex.EncodeToString(salt))
	}

	// 2. Load the SETUP header for password parameters
	file, err := osOpen(exePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	table, err := ParseSetupLdr(exePath)
	if err != nil {
		return nil, err
	}

	headerSchema, _ := GetRecordSchema(ver, "TSetupHeader", isUnicode)
	setup0BlockOffset := table.Offset0 + 64
	if ver >= 6500 {
		setup0BlockOffset += 4 + 49
	}
	if _, err := file.Seek(setup0BlockOffset, ioSeekStart); err != nil {
		return nil, err
	}
	blockHeader, err := ReadBlockHeader(file, ver)
	if err != nil {
		return nil, fmt.Errorf("failed to read block header: %w", err)
	}
	compMethod := getSetup0CompressionMethod(ver)
	blockReader, err := NewBlockReader(file, blockHeader, compMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize block reader: %w", err)
	}
	defer blockReader.Close()

	parsedHeader, err := ReadRecord(blockReader, headerSchema, isUnicode)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SETUP header: %w", err)
	}

	// 3. Script String Extraction (Forensic Auto-Cracking)
	var extractedCandidates []string
	var compiledCodeBytes []byte

	if isUnicode {
		if len(parsedHeader.AnsiStrings) >= 4 {
			compiledCodeBytes = []byte(parsedHeader.AnsiStrings[3])
		}
	} else {
		if len(parsedHeader.AnsiStrings) >= 31 {
			compiledCodeBytes = []byte(parsedHeader.AnsiStrings[30])
		}
	}

	if len(compiledCodeBytes) > 0 {
		extractedCandidates = ExtractPrintableStrings(compiledCodeBytes)
		fmt.Printf("[*] Extracted %d potential password keys from CompiledCode bytecode.\n", len(extractedCandidates))
	}

	// Prepend extracted candidates to the wordlist so we check them first
	fullWordlist := append(extractedCandidates, wordlist...)

	// Remove duplicates from fullWordlist to keep it highly efficient
	uniqueWordlist := make([]string, 0, len(fullWordlist))
	seen := make(map[string]bool)
	for _, w := range fullWordlist {
		if !seen[w] {
			seen[w] = true
			uniqueWordlist = append(uniqueWordlist, w)
		}
	}

	// 4. Coordinate recovery channels
	numCPUs := runtime.NumCPU()
	wordsChan := make(chan string, 100)
	resultsChan := make(chan string, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Determine encryption parameters
	if ver < 6400 {
		// v5 Crypt (MD5 or SHA1 hash blocks)
		if len(expectedHash) == 0 {
			return nil, errors.New("installer does not appear to be password protected (missing PasswordHash)")
		}

		// SHA1 digests are 20 bytes; MD5 digests are 16 bytes
		isSHA1 := len(expectedHash) == 20
		hashType := "MD5"
		if isSHA1 {
			hashType = "SHA-1"
		}

		// Spawn CPU worker routines
		for i := 0; i < numCPUs; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case word, ok := <-wordsChan:
						if !ok {
							return
						}
						if VerifyPassword_v5(word, expectedHash, salt, isSHA1, isUnicode) {
							select {
							case resultsChan <- word:
								cancel()
							default:
							}
							return
						}
					}
				}
			}()
		}

		// Feed wordlist
		go func() {
			for _, word := range uniqueWordlist {
				select {
				case <-ctx.Done():
					break
				case wordsChan <- word:
				}
			}
			close(wordsChan)
		}()

		wg.Wait()
		close(resultsChan)

		recovered, found := <-resultsChan
		return &PasswordCrackResult{
			PasswordFound: found,
			Password:      recovered,
			HashType:      hashType,
			TotalGuesses:  int64(len(uniqueWordlist)),
		}, nil

	} else {
		// v6 Crypt (PBKDF2-SHA256 + ChaCha20 zeroes verification test)
		if crypt64 == nil {
			return nil, errors.New("modern installer missing expected cryptographic metadata block")
		}

		// Spawn CPU worker routines
		for i := 0; i < numCPUs; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case word, ok := <-wordsChan:
						if !ok {
							return
						}
						if VerifyPassword_v6(word, crypt64.PasswordTest, crypt64.KDFSalt, crypt64.KDFIterations, crypt64.BaseNonce) {
							select {
							case resultsChan <- word:
								cancel()
							default:
							}
							return
						}
					}
				}
			}()
		}

		// Feed wordlist
		go func() {
			for _, word := range uniqueWordlist {
				select {
				case <-ctx.Done():
					break
				case wordsChan <- word:
				}
			}
			close(wordsChan)
		}()

		wg.Wait()
		close(resultsChan)

		recovered, found := <-resultsChan
		return &PasswordCrackResult{
			PasswordFound: found,
			Password:      recovered,
			HashType:      "PBKDF2-SHA256-ChaCha20",
			TotalGuesses:  int64(len(uniqueWordlist)),
		}, nil
	}
}

// ExtractPrintableStrings scans a byte slice and extracts printable ASCII and UTF-16LE strings.
func ExtractPrintableStrings(data []byte) []string {
	var candidates []string

	// 1. Scan standard ASCII sequences (printable chars 0x20 to 0x7E)
	var curASCII []byte
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			curASCII = append(curASCII, b)
		} else {
			if len(curASCII) >= 6 {
				candidates = append(candidates, string(curASCII))
			}
			curASCII = nil
		}
	}
	if len(curASCII) >= 6 {
		candidates = append(candidates, string(curASCII))
	}

	// 2. Scan UTF-16LE sequences (alternating printable byte + null byte)
	var curUTF16 []byte
	for i := 0; i < len(data)-1; i += 2 {
		b := data[i]
		nullByte := data[i+1]
		if (b >= 0x20 && b <= 0x7E) && nullByte == 0x00 {
			curUTF16 = append(curUTF16, b)
		} else {
			if len(curUTF16) >= 6 {
				candidates = append(candidates, string(curUTF16))
			}
			curUTF16 = nil
		}
	}
	if len(curUTF16) >= 6 {
		candidates = append(candidates, string(curUTF16))
	}

	return candidates
}

// Wrapper helper to open file
func osOpen(path string) (*os.File, error) {
	return os.Open(path)
}

const (
	ioSeekStart = 0
)
