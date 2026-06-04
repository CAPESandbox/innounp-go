package parser

import (
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
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

func (d *DecryptReader) Read(p []byte) (n int, err error) {
	n, err = d.underlying.Read(p)
	if n > 0 {
		if d.cipherRC4 != nil {
			d.cipherRC4.XORKeyStream(p[:n], p[:n])
		} else if d.cipherCC20 != nil {
			d.cipherCC20.XORKeyStream(p[:n], p[:n])
		}
	}
	return n, err
}

// UnifiedFileLocationEntry mirrors the parsed properties of a TSetupFileLocationEntry.
type UnifiedFileLocationEntry struct {
	FirstSlice          int32
	LastSlice           int32
	StartOffset         int32
	ChunkSuboffset      int64
	OriginalSize        int64
	ChunkCompressedSize int64
	SHA1Sum             []byte
	Flags               uint32
}

// Helper to check if a bit flag is set
func hasFlag(flags uint32, bit uint) bool {
	return (flags & (1 << bit)) != 0
}

// ExtractFile extracts and decrypts/decompresses a single file from the Inno Setup executable.
func ExtractFile(
	exePath string,
	table *UnifiedOffsetTable,
	ver int,
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

	// 2. Read and verify 4-byte chunk ID: 'zlb'#26 (0x1A626C7A)
	var compID uint32
	if err := binary.Read(file, binary.LittleEndian, &compID); err != nil {
		return fmt.Errorf("failed to read comp ID: %w", err)
	}
	if compID != 0x1A626C7A {
		return errors.New("invalid compression ID: source block is corrupted")
	}

	// 3. Initialize CRC-validated chunk reader
	chunkReader := NewCRCChunkReader(file, fl.ChunkCompressedSize)

	var decryptReader io.Reader = chunkReader

	// 4. Handle Decryption if the chunk is encrypted
	if hasFlag(fl.Flags, 6) { // foChunkEncrypted is bit 6
		if password == "" {
			return errors.New("file is encrypted but no password was specified")
		}

		if ver < 6400 {
			// v5 decryption uses an 8-byte salt read directly from the stream
			salt := make([]byte, 8)
			if _, err := io.ReadFull(chunkReader, salt); err != nil {
				return fmt.Errorf("failed to read encryption salt: %w", err)
			}

			cipher, err := InitializeRC4Decryptor(password, salt, true, true) // modern v5 uses SHA-1 and Unicode
			if err != nil {
				return fmt.Errorf("failed to initialize RC4 decryptor: %w", err)
			}
			decryptReader = &DecryptReader{underlying: chunkReader, cipherRC4: cipher}
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
			decryptReader = &DecryptReader{underlying: chunkReader, cipherCC20: cipher}
		}
	}

	// 5. Initialize Decompressor Stream
	var decompressor io.ReadCloser
	if hasFlag(fl.Flags, 7) { // foChunkCompressed is bit 7
		// Create decompressed reader using the decompressor factory we built in Phase 2
		hdr := &BlockHeader{
			StoredSize: fl.ChunkCompressedSize,
			Compressed: true,
		}
		if hasFlag(fl.Flags, 6) && ver < 6400 {
			// If encrypted, the salt (8 bytes) was already consumed, so adjust size
			hdr.StoredSize -= 8
		}

		var err error
		decompressor, err = NewBlockReader(decryptReader, hdr, compressMethod)
		if err != nil {
			return fmt.Errorf("failed to initialize decompressor: %w", err)
		}
	} else {
		// Not compressed
		decompressor = io.NopCloser(decryptReader)
	}
	defer decompressor.Close()

	// 6. Navigate/Discard bytes up to the file's ChunkSuboffset
	if fl.ChunkSuboffset > 0 {
		discarded, err := io.CopyN(io.Discard, decompressor, fl.ChunkSuboffset)
		if err != nil || discarded != fl.ChunkSuboffset {
			return fmt.Errorf("failed to seek to chunk suboffset: %w", err)
		}
	}

	// 7. Reconstruct parent directories on disk
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// 8. Extract loop, checksum tracking, and CALL/JMP absolute conversion
	bytesLeft := fl.OriginalSize
	buf := make([]byte, 65536)
	var addrOffset uint32

	// We calculate CRC32 of the uncompressed data for verification
	crcHash := crc32.NewIEEE()
	var sha256Hash hash.Hash // SHA-256 for modern blocks if needed

	for bytesLeft > 0 {
		chunk := int64(len(buf))
		if bytesLeft < chunk {
			chunk = bytesLeft
		}

		n, err := io.ReadFull(decompressor, buf[:chunk])
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read decompressed stream: %w", err)
		}
		if n == 0 {
			break
		}

		// Apply absolute x86/x64 call optimization filter if enabled
		if hasFlag(fl.Flags, 4) { // foCallInstructionOptimized is bit 4
			if ver >= 5309 {
				TransformCallInstructions5309(buf[:n], addrOffset, false)
			} else {
				TransformCallInstructions(buf[:n], addrOffset, false)
			}
			addrOffset += uint32(n)
		}

		// Track hashes
		crcHash.Write(buf[:n])
		if sha256Hash != nil {
			sha256Hash.Write(buf[:n])
		}

		// Write to output file
		if _, err := destFile.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write extracted file bytes: %w", err)
		}

		bytesLeft -= int64(n)
	}

	if bytesLeft > 0 {
		return errors.New("failed to extract file: truncated stream payload")
	}

	return nil
}

// Is64EncryptionData holds PBKDF2 iterations, salt, and base nonce for v6 decryption.
type Is64EncryptionData struct {
	PasswordTest  int32
	KDFSalt       []byte
	KDFIterations int
	BaseNonce     []byte
}
