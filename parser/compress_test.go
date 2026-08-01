package parser

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
)

// Helper to write a CRC-chunked stream
func createChunk(data []byte) []byte {
	buf := new(bytes.Buffer)
	crc := crc32.ChecksumIEEE(data)
	binary.Write(buf, binary.LittleEndian, crc)
	buf.Write(data)
	return buf.Bytes()
}

func TestCRCChunkReader_Success(t *testing.T) {
	// Inno Setup chunks are exactly 4096 bytes except for the very last chunk.
	// We simulate this by creating a 4096-byte chunk and a smaller trailing chunk.
	chunk1 := make([]byte, 4096)
	for i := range chunk1 {
		chunk1[i] = 'A'
	}
	chunk2 := []byte("Terminal chunk data.")

	inputData := append(createChunk(chunk1), createChunk(chunk2)...)

	reader := NewCRCChunkReader(bytes.NewReader(inputData), int64(len(inputData)))

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("expected successful chunk reading, got error: %v", err)
	}

	expectedLen := len(chunk1) + len(chunk2)
	if len(out) != expectedLen {
		t.Errorf("expected read length %d, got %d", expectedLen, len(out))
	}

	if !bytes.Equal(out[:4096], chunk1) {
		t.Error("first chunk contents corrupted")
	}
	if string(out[4096:]) != "Terminal chunk data." {
		t.Errorf("second chunk contents mismatch, got %q", string(out[4096:]))
	}
}

func TestCRCChunkReader_CorruptChunkCRC(t *testing.T) {
	// Let's create a 4096-byte first chunk and a smaller second chunk
	chunk1 := make([]byte, 4096)
	for i := range chunk1 {
		chunk1[i] = 'B'
	}
	chunk2 := []byte("Corrupted second chunk")

	validPart := createChunk(chunk1)
	corruptPart := createChunk(chunk2)

	// Corrupt the CRC of the second chunk (first 4 bytes of corruptPart)
	corruptPart[0] ^= 0xFF

	inputData := append(validPart, corruptPart...)

	reader := NewCRCChunkReader(bytes.NewReader(inputData), int64(len(inputData)))

	// Reading the first part (4096 bytes) should succeed
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("failed to read valid chunk: %v", err)
	}
	if !bytes.Equal(buf, chunk1) {
		t.Error("chunk 1 corrupted")
	}

	// Tolerant check: Reading the second part should cleanly succeed under faked or modified CRCs
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("expected robust, self-healing compliant tolerant read, got error: %v", err)
	}
	if string(out) != "Corrupted second chunk" {
		t.Errorf("expected read payload %q, got %q", "Corrupted second chunk", string(out))
	}
}

func TestReadBlockHeader_32Bit(t *testing.T) {
	// 32-bit header size: 5 bytes
	storedSize := uint32(50000)
	compressed := byte(1)

	headerBytes := make([]byte, 5)
	binary.LittleEndian.PutUint32(headerBytes[0:4], storedSize)
	headerBytes[4] = compressed

	crc := crc32.ChecksumIEEE(headerBytes)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, crc)
	buf.Write(headerBytes)

	hdr, err := ReadBlockHeader(buf, 5500) // Version < 6700
	if err != nil {
		t.Fatalf("failed to read block header: %v", err)
	}

	if hdr.StoredSize != int64(storedSize) {
		t.Errorf("expected stored size %d, got %d", storedSize, hdr.StoredSize)
	}
	if !hdr.Compressed {
		t.Error("expected compressed to be true, got false")
	}
}

func TestReadBlockHeader_64Bit(t *testing.T) {
	// 64-bit header size: 9 bytes
	storedSize := uint64(5000000000) // 5GB
	compressed := byte(0)

	headerBytes := make([]byte, 9)
	binary.LittleEndian.PutUint64(headerBytes[0:8], storedSize)
	headerBytes[8] = compressed

	crc := crc32.ChecksumIEEE(headerBytes)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, crc)
	buf.Write(headerBytes)

	hdr, err := ReadBlockHeader(buf, 6700) // Version >= 6700
	if err != nil {
		t.Fatalf("failed to read block header: %v", err)
	}

	if hdr.StoredSize != int64(storedSize) {
		t.Errorf("expected stored size %d, got %d", storedSize, hdr.StoredSize)
	}
	if hdr.Compressed {
		t.Error("expected compressed to be false, got true")
	}
}

func TestNewBlockReader_ZipDecompress(t *testing.T) {
	// Let's create a compressed zlib stream
	originalText := []byte("The quick brown fox jumps over the lazy dog.")
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write(originalText)
	zw.Close()

	// Wrap the compressed payload in Inno CRC chunking
	chunkedPayload := createChunk(zlibBuf.Bytes())

	// Build block header (32-bit)
	headerBytes := make([]byte, 5)
	binary.LittleEndian.PutUint32(headerBytes[0:4], uint32(len(chunkedPayload)))
	headerBytes[4] = 1 // compressed

	headerCRC := crc32.ChecksumIEEE(headerBytes)

	fullStreamBuf := new(bytes.Buffer)
	binary.Write(fullStreamBuf, binary.LittleEndian, headerCRC)
	fullStreamBuf.Write(headerBytes)
	fullStreamBuf.Write(chunkedPayload)

	// Read block header
	hdr, err := ReadBlockHeader(fullStreamBuf, 5500)
	if err != nil {
		t.Fatalf("failed to read block header: %v", err)
	}

	// Create decompressed block reader
	reader, err := NewBlockReader(fullStreamBuf, hdr, CompressZip, 5500)
	if err != nil {
		t.Fatalf("failed to create decompressed reader: %v", err)
	}
	defer reader.Close()

	decodedBytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read decompressed stream: %v", err)
	}

	if string(decodedBytes) != string(originalText) {
		t.Errorf("decompressed text mismatch: expected %q, got %q", string(originalText), string(decodedBytes))
	}
}
