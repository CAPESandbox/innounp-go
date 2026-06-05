package parser

import (
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20"
)

// DecryptReader is a helper io.Reader that decrypts stream bytes on the fly.
type DecryptReader struct {
	underlying io.Reader
	cipherRC4  *rc4.Cipher
	cipherCC20 *chacha20.Cipher
}

func (r *DecryptReader) Read(p []byte) (int, error) {
	n, err := r.underlying.Read(p)
	if n > 0 {
		if r.cipherRC4 != nil {
			r.cipherRC4.XORKeyStream(p[:n], p[:n])
		} else if r.cipherCC20 != nil {
			r.cipherCC20.XORKeyStream(p[:n], p[:n])
		}
	}
	return n, err
}

// ExtractFile extracts and decrypts/decompresses a single file from the Inno Setup executable.
func ExtractFile(
	exePath string,
	table *UnifiedOffsetTable,
	ver int,
	isUnicode bool,
	fl *UnifiedFileLocationEntry,
	destPath string,
	compressMethod SetupCompressMethod,
	password string,
	is64Encryption *Is64EncryptionData,
) error {
	file, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("failed to open executable: %w", err)
	}
	defer file.Close()

	// 1. Seek to chunk start offset inside the embedded payload
	absOffset := table.Offset1 + int64(fl.StartOffset)
	if _, err := file.Seek(absOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to chunk start offset at %d: %w", absOffset, err)
	}

	// 2. Read and verify unencrypted 4-byte chunk ID: 'zlb'#26 (0x1A626C7A)
	var compID uint32
	if err := binary.Read(file, binary.LittleEndian, &compID); err != nil {
		return fmt.Errorf("failed to read comp ID: %w", err)
	}
	if compID != 0x1A626C7A {
		return errors.New("invalid compression ID: source block is corrupted")
	}

	var rawReader io.Reader = file
	var salt []byte

	// 3. Handle Decryption if the chunk is encrypted (apply decryption starting immediately after the chunk ID)
	if hasFlag(fl.Flags, 6) { // foChunkEncrypted is bit 6
		if password == "" {
			return errors.New("file is encrypted but no password was specified")
		}

		if ver < 6400 {
			// v5 decryption uses an 8-byte salt read directly from the stream
			salt = make([]byte, 8)
			if _, err := io.ReadFull(file, salt); err != nil {
				return fmt.Errorf("failed to read encryption salt: %w", err)
			}

			cipher, err := InitializeRC4Decryptor(password, salt, true, isUnicode) // Pass actual isUnicode flag!
			if err != nil {
				return fmt.Errorf("failed to initialize RC4 decryptor: %w", err)
			}
			rawReader = &DecryptReader{underlying: file, cipherRC4: cipher}
		} else {
			// v6 decryption uses PBKDF2 derived keys and BaseNonce XOR offsets
			if is64Encryption == nil {
				return errors.New("missing v6 encryption configuration")
			}

			key := GenerateChaCha20Key(password, is64Encryption.KDFSalt, is64Encryption.KDFIterations)
			nonce := RecreateChaCha20Nonce(is64Encryption.BaseNonce, int64(fl.StartOffset), fl.FirstSlice)

			cipher, err := InitializeChaCha20Decryptor(key, nonce)
			if err != nil {
				return fmt.Errorf("failed to initialize ChaCha20 decryptor: %w", err)
			}
			rawReader = &DecryptReader{underlying: file, cipherCC20: cipher}
		}
	}

	// 4. Initialize Decompressor Stream directly over the decrypted rawReader!
	// Payload files streams are pure continuous compressed streams without block headers or segmented CRCs.
	decompressor, err := NewDecompressor(rawReader, compressMethod)
	if err != nil {
		return fmt.Errorf("failed to initialize decompressor: %w", err)
	}
	defer decompressor.Close()

	// 6. Skip sub-offset bytes inside chunk to locate current file payload start boundary
	if fl.ChunkSuboffset > 0 {
		if _, err := io.CopyN(io.Discard, decompressor, fl.ChunkSuboffset); err != nil {
			return fmt.Errorf("failed to seek to chunk sub-offset %d: %w", fl.ChunkSuboffset, err)
		}
	}

	// 7. Write decompressed payload to target destination file with Anti-Size-Bomb defensive shield
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Setup Call/JMP instruction de-optimizer filters
	var bytesWritten uint32 = 0
	var callOptFilter func([]byte, uint32)
	if hasFlag(fl.Flags, 4) { // foCallInstructionOptimized is bit 4
		if ver >= 5309 {
			callOptFilter = func(b []byte, offset uint32) {
				TransformCallInstructions5309(b, uint32(fl.ChunkSuboffset)+offset, false)
			}
		} else {
			callOptFilter = func(b []byte, offset uint32) {
				TransformCallInstructions(b, uint32(fl.ChunkSuboffset)+offset, false)
			}
		}
	}

	var sha256Hash hash.Hash
	if ver >= 6400 {
		// SHA256 validation (Inno 6.x+)
		// (Initialize hashing here if needed downstream)
	}

	// Use Anti-Size-Bomb Defensive Shield: Capped bytes left to read using the actual physical file size
	// to prevent artificial OOM/sandbox sandbox crashes (deflating bombs).
	stat, err := file.Stat()
	var maxReadableBytes int64 = 0
	if err == nil {
		maxReadableBytes = stat.Size() - table.Offset1
	}
	if fl.OriginalSize > maxReadableBytes && maxReadableBytes > 0 {
		return fmt.Errorf("defensive shield: file size %d exceeds physical readable boundary %d", fl.OriginalSize, maxReadableBytes)
	}

	buf := make([]byte, 64*1024)
	bytesLeft := fl.OriginalSize
	for bytesLeft > 0 {
		toRead := int64(len(buf))
		if toRead > bytesLeft {
			toRead = bytesLeft
		}

		n, err := io.ReadFull(decompressor, buf[:toRead])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return fmt.Errorf("failed to read payload bytes: %w", err)
		}
		if n == 0 {
			break
		}

		// Apply instruction de-optimization filters
		if callOptFilter != nil {
			callOptFilter(buf[:n], bytesWritten)
		}

		if sha256Hash != nil {
			sha256Hash.Write(buf[:n])
		}

		// Write to output file
		if _, err := destFile.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write extracted file bytes: %w", err)
		}

		bytesWritten += uint32(n)
		bytesLeft -= int64(n)
	}

	return nil
}
