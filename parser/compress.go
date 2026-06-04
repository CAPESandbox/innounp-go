package parser

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// SetupCompressMethod specifies the compression format of the installer.
type SetupCompressMethod int

const (
	CompressStored SetupCompressMethod = iota
	CompressZip
	CompressBzip
	CompressLZMA
	CompressLZMA2
)

// BlockHeader defines the metadata of a compressed block (e.g. SETUP.0).
type BlockHeader struct {
	StoredSize int64 // Total bytes of subsequent chunked data on disk (including chunk CRCs)
	Compressed bool  // True if the block is compressed, False if stored (uncompressed)
}

// ReadBlockHeader reads and validates a compressed block header from the current position.
// Layout varies:
// - Versions < 6.7.0 (Ver < 6700): 4-byte CRC + 5-byte header (4-byte StoredSize + 1-byte Compressed)
// - Versions >= 6.7.0 (Ver >= 6700): 4-byte CRC + 9-byte header (8-byte StoredSize + 1-byte Compressed)
func ReadBlockHeader(r io.Reader, ver int) (*BlockHeader, error) {
	var crcExpected uint32
	if err := binary.Read(r, binary.LittleEndian, &crcExpected); err != nil {
		return nil, fmt.Errorf("failed to read block header CRC: %w", err)
	}

	var headerBytes []byte
	var storedSize int64
	var compressed bool

	if ver < 6700 {
		// 32-bit Header: 4-byte StoredSize + 1-byte Compressed = 5 bytes
		headerBytes = make([]byte, 5)
		if _, err := io.ReadFull(r, headerBytes); err != nil {
			return nil, fmt.Errorf("failed to read 32-bit block header: %w", err)
		}

		sz := binary.LittleEndian.Uint32(headerBytes[0:4])
		storedSize = int64(sz)
		compressed = headerBytes[4] != 0
	} else {
		// 64-bit Header: 8-byte StoredSize + 1-byte Compressed = 9 bytes
		headerBytes = make([]byte, 9)
		if _, err := io.ReadFull(r, headerBytes); err != nil {
			return nil, fmt.Errorf("failed to read 64-bit block header: %w", err)
		}

		storedSize = int64(binary.LittleEndian.Uint64(headerBytes[0:8]))
		compressed = headerBytes[8] != 0
	}

	// Verify Header CRC
	actualCRC := crc32.ChecksumIEEE(headerBytes)
	if actualCRC != crcExpected {
		return nil, errors.New("corrupted block header: CRC mismatch")
	}

	return &BlockHeader{
		StoredSize: storedSize,
		Compressed: compressed,
	}, nil
}

// CRCChunkReader is an io.Reader that processes, strips, and verifies
// Inno Setup's 4-byte CRC segmented chunks on the fly.
type CRCChunkReader struct {
	underlying io.Reader
	buffer     []byte
	avail      int
	next       int
	bytesLeft  int64
}

// NewCRCChunkReader wraps an input stream as a CRC-validated chunk streamer.
func NewCRCChunkReader(r io.Reader, totalStoredSize int64) *CRCChunkReader {
	return &CRCChunkReader{
		underlying: r,
		buffer:     make([]byte, 4096),
		bytesLeft:  totalStoredSize,
	}
}

func (c *CRCChunkReader) Read(p []byte) (n int, err error) {
	if c.avail == 0 {
		if c.bytesLeft <= 0 {
			return 0, io.EOF
		}
		if err := c.readNextChunk(); err != nil {
			return 0, err
		}
	}

	n = copy(p, c.buffer[c.next:c.next+c.avail])
	c.next += n
	c.avail -= n
	return n, nil
}

func (c *CRCChunkReader) readNextChunk() error {
	// Each chunk starts with a 4-byte CRC32
	if c.bytesLeft < 4 {
		return fmt.Errorf("corrupted stream: unexpected end of stream when reading chunk CRC (need 4 bytes, left %d)", c.bytesLeft)
	}

	var crcExpected uint32
	if err := binary.Read(c.underlying, binary.LittleEndian, &crcExpected); err != nil {
		return fmt.Errorf("failed to read chunk CRC: %w", err)
	}
	c.bytesLeft -= 4

	// Determine subsequent chunk data size (up to 4096)
	chunkSize := int64(4096)
	if c.bytesLeft < chunkSize {
		chunkSize = c.bytesLeft
	}

	if chunkSize <= 0 {
		return fmt.Errorf("corrupted stream: invalid chunk size %d", chunkSize)
	}

	// Read chunk data bytes
	if _, err := io.ReadFull(c.underlying, c.buffer[:chunkSize]); err != nil {
		return fmt.Errorf("failed to read chunk data: %w", err)
	}
	c.bytesLeft -= chunkSize

	// Verify Chunk CRC32
	actualCRC := crc32.ChecksumIEEE(c.buffer[:chunkSize])
	if actualCRC != crcExpected {
		return fmt.Errorf("corrupted chunk data: CRC mismatch (expected 0x%X, got 0x%X)", crcExpected, actualCRC)
	}

	c.next = 0
	c.avail = int(chunkSize)
	return nil
}

// NewBlockReader returns a decompressed read-closer stream for the given block.
func NewBlockReader(r io.Reader, header *BlockHeader, method SetupCompressMethod) (io.ReadCloser, error) {
	// 1. Wrap the stream in our custom CRCChunkReader
	chunkReader := NewCRCChunkReader(r, header.StoredSize)

	// 2. If the block is not compressed, serve the CRCChunkReader directly
	if !header.Compressed || method == CompressStored {
		return io.NopCloser(chunkReader), nil
	}

	// 3. Wrap in appropriate decompression pipeline
	switch method {
	case CompressZip:
		zReader, err := zlib.NewReader(chunkReader)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize zlib decompressor: %w", err)
		}
		return zReader, nil

	case CompressBzip:
		bzReader := bzip2.NewReader(chunkReader)
		return io.NopCloser(bzReader), nil

	case CompressLZMA:
		// Read 5-byte properties header from the stream: [1-byte properties] [4-byte dictionary size]
		props := make([]byte, 5)
		if _, err := io.ReadFull(chunkReader, props); err != nil {
			return nil, fmt.Errorf("failed to read LZMA properties: %w", err)
		}

		// Synthesize standard 13-byte classic LZMA header by appending 8 bytes of uncompressed size (unknown = 0xFF...)
		header13 := make([]byte, 13)
		copy(header13[0:5], props)
		for i := 5; i < 13; i++ {
			header13[i] = 0xFF
		}

		// Prepend the synthesized header back to the stream
		combinedReader := io.MultiReader(bytes.NewReader(header13), chunkReader)

		lzReader, err := lzma.NewReader(combinedReader)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize LZMA decompressor: %w", err)
		}
		return io.NopCloser(lzReader), nil

	case CompressLZMA2:
		// Read 1-byte property header representing dictionary size
		var prop byte
		if err := binary.Read(chunkReader, binary.LittleEndian, &prop); err != nil {
			return nil, fmt.Errorf("failed to read LZMA2 property: %w", err)
		}

		dictSize := lzma2DictSizeFromProp(prop)

		// Configure standard LZMA2 reader
		config := lzma.Reader2Config{
			DictCap: dictSize,
		}

		lz2Reader, err := config.NewReader2(chunkReader)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize LZMA2 decompressor (dictionary size %d): %w", dictSize, err)
		}
		return io.NopCloser(lz2Reader), nil

	default:
		return nil, fmt.Errorf("unsupported compression method: %d", method)
	}
}

// lzma2DictSizeFromProp calculates dictionary size from the LZMA2 1-byte property
func lzma2DictSizeFromProp(p byte) int {
	return int((2 | (uint32(p) & 1)) << (uint32(p)/2 + 11))
}
