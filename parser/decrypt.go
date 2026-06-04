package parser

import (
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/pbkdf2"
)

// DerivePasswordHashSHA1 derives the 20-byte SHA-1 password verification hash.
func DerivePasswordHashSHA1(password string, salt []byte, isUnicode bool) []byte {
	h := sha1.New()
	h.Write([]byte("PasswordCheckHash"))
	h.Write(salt)

	if isUnicode {
		// Encode to UTF-16LE bytes
		runes := []rune(password)
		u16s := utf16.Encode(runes)
		buf := make([]byte, len(u16s)*2)
		for i, v := range u16s {
			binary.LittleEndian.PutUint16(buf[i*2:i*2+2], v)
		}
		h.Write(buf)
	} else {
		h.Write([]byte(password))
	}

	return h.Sum(nil)
}

// DerivePasswordHashMD5 derives the 16-byte MD5 password verification hash.
func DerivePasswordHashMD5(password string, salt []byte) []byte {
	h := md5.New()
	h.Write([]byte("PasswordCheckHash"))
	h.Write(salt)
	h.Write([]byte(password))
	return h.Sum(nil)
}

// InitializeRC4Decryptor creates and initializes an RC4 cipher.
// Inno Setup discards the first 1000 bytes of the cipher stream for security.
func InitializeRC4Decryptor(password string, salt []byte, isSHA1 bool, isUnicode bool) (*rc4.Cipher, error) {
	var key []byte

	if isSHA1 {
		// SHA1 key derivation: SHA1(salt + password)
		h := sha1.New()
		h.Write(salt)
		if isUnicode {
			runes := []rune(password)
			u16s := utf16.Encode(runes)
			buf := make([]byte, len(u16s)*2)
			for i, v := range u16s {
				binary.LittleEndian.PutUint16(buf[i*2:i*2+2], v)
			}
			h.Write(buf)
		} else {
			h.Write([]byte(password))
		}
		key = h.Sum(nil)
	} else {
		// MD5 key derivation: MD5(salt + password)
		h := md5.New()
		h.Write(salt)
		h.Write([]byte(password))
		key = h.Sum(nil)
	}

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Discard the first 1000 bytes as required by Inno Setup
	discard := make([]byte, 1000)
	cipher.XORKeyStream(discard, discard)

	return cipher, nil
}

// GenerateChaCha20Key derives a 32-byte key using PBKDF2-SHA256.
func GenerateChaCha20Key(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

// RecreateChaCha20Nonce derives the unique 24-byte nonce from the base nonce.
func RecreateChaCha20Nonce(baseNonce []byte, chunkStartOffset int64, chunkFirstSlice int32) []byte {
	nonce := make([]byte, 24)
	copy(nonce, baseNonce)

	// Inno's BaseNonce format has:
	// RandomXorStartOffset (Int64, first 8 bytes) xor ChunkStartOffset
	// RandomXorFirstSlice (Int32, next 4 bytes) xor ChunkFirstSlice
	startOffsetVal := binary.LittleEndian.Uint64(nonce[0:8])
	binary.LittleEndian.PutUint64(nonce[0:8], startOffsetVal^uint64(chunkStartOffset))

	firstSliceVal := binary.LittleEndian.Uint32(nonce[8:12])
	binary.LittleEndian.PutUint32(nonce[8:12], firstSliceVal^uint32(chunkFirstSlice))

	return nonce
}

// InitializeChaCha20Decryptor creates and initializes an XChaCha20 cipher.
func InitializeChaCha20Decryptor(key []byte, nonce []byte) (*chacha20.Cipher, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length for ChaCha20 (must be 32 bytes)")
	}
	if len(nonce) != 24 {
		return nil, errors.New("invalid nonce length for XChaCha20 (must be 24 bytes)")
	}

	return chacha20.NewUnauthenticatedCipher(key, nonce)
}

// VerifyPassword_v5 verifies password correctness for Inno Setup 5 (SHA1 or MD5-based).
func VerifyPassword_v5(password string, expectedHash []byte, salt []byte, isSHA1 bool, isUnicode bool) bool {
	if isSHA1 {
		actualHash := DerivePasswordHashSHA1(password, salt, isUnicode)
		if len(actualHash) != len(expectedHash) {
			return false
		}
		for i := range actualHash {
			if actualHash[i] != expectedHash[i] {
				return false
			}
		}
		return true
	}

	actualHash := DerivePasswordHashMD5(password, salt)
	if len(actualHash) != len(expectedHash) {
		return false
	}
	for i := range actualHash {
		if actualHash[i] != expectedHash[i] {
			return false
		}
	}
	return true
}

// VerifyPassword_v6 verifies password correctness for Inno Setup 6 (ChaCha20-based).
func VerifyPassword_v6(password string, expectedPasswordTest int32, kdfSalt []byte, kdfIterations int, baseNonce []byte) bool {
	// Derive key
	key := GenerateChaCha20Key(password, kdfSalt, kdfIterations)

	// Setup nonce: BaseNonce with RandomXorFirstSlice xor -1 (0xFFFFFFFF)
	nonce := make([]byte, 24)
	copy(nonce, baseNonce)

	firstSliceVal := binary.LittleEndian.Uint32(nonce[8:12])
	binary.LittleEndian.PutUint32(nonce[8:12], firstSliceVal^0xFFFFFFFF)

	cipher, err := InitializeChaCha20Decryptor(key, nonce)
	if err != nil {
		return false
	}

	// Encrypt 4 bytes of zeros (PasswordTest)
	testBuf := make([]byte, 4)
	cipher.XORKeyStream(testBuf, testBuf)

	actualTest := int32(binary.LittleEndian.Uint32(testBuf))
	return actualTest == expectedPasswordTest
}
