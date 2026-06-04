package parser

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestVerifyPassword_v5_SHA1_Unicode(t *testing.T) {
	password := "SecretPass123"
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Compute expected hash: SHA1("PasswordCheckHash" + salt + UTF16LE(password))
	expectedHash := DerivePasswordHashSHA1(password, salt, true)

	if !VerifyPassword_v5(password, expectedHash, salt, true, true) {
		t.Error("expected correct password verification to pass, but it failed")
	}

	if VerifyPassword_v5("WrongPass", expectedHash, salt, true, true) {
		t.Error("expected incorrect password verification to fail, but it passed")
	}
}

func TestVerifyPassword_v5_MD5(t *testing.T) {
	password := "MD5Pass"
	salt := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}

	expectedHash := DerivePasswordHashMD5(password, salt)

	if !VerifyPassword_v5(password, expectedHash, salt, false, false) {
		t.Error("expected MD5 password verification to pass, but it failed")
	}

	if VerifyPassword_v5("WrongPass", expectedHash, salt, false, false) {
		t.Error("expected incorrect MD5 password verification to fail, but it passed")
	}
}

func TestVerifyPassword_v6_Success(t *testing.T) {
	password := "ChaChaPassword"
	kdfSalt := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	kdfIterations := 5 // low iterations for speed in tests
	baseNonce := make([]byte, 24)
	for i := range baseNonce {
		baseNonce[i] = byte(i + 1)
	}

	// To generate expectedPasswordTest, we run the encryption ourselves:
	key := GenerateChaCha20Key(password, kdfSalt, kdfIterations)
	nonce := make([]byte, 24)
	copy(nonce, baseNonce)
	firstSliceVal := binary.LittleEndian.Uint32(nonce[8:12])
	binary.LittleEndian.PutUint32(nonce[8:12], firstSliceVal^0xFFFFFFFF)

	cipher, err := InitializeChaCha20Decryptor(key, nonce)
	if err != nil {
		t.Fatalf("failed to initialize cipher: %v", err)
	}
	testBuf := make([]byte, 4)
	cipher.XORKeyStream(testBuf, testBuf)
	expectedPasswordTest := int32(binary.LittleEndian.Uint32(testBuf))

	// Verify
	if !VerifyPassword_v6(password, expectedPasswordTest, kdfSalt, kdfIterations, baseNonce) {
		t.Error("expected correct ChaCha20 password verification to succeed, but it failed")
	}

	if VerifyPassword_v6("WrongPassword", expectedPasswordTest, kdfSalt, kdfIterations, baseNonce) {
		t.Error("expected wrong ChaCha20 password to fail, but it succeeded")
	}
}

func TestRC4Decryptor_DiscardBlocks(t *testing.T) {
	password := "RC4Secure"
	salt := []byte{0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05}

	// Create decryptor
	dec, err := InitializeRC4Decryptor(password, salt, true, true)
	if err != nil {
		t.Fatalf("failed to initialize RC4: %v", err)
	}

	// Since RC4 has a 1000-byte discard check, a stream encrypted directly with key
	// will NOT match unless we discard 1000 bytes first.
	plaintext := []byte("Sensitive secret installer data")
	ciphertext := make([]byte, len(plaintext))

	rawCipher, _ := InitializeRC4Decryptor(password, salt, true, true)
	rawCipher.XORKeyStream(ciphertext, plaintext)

	decrypted := make([]byte, len(plaintext))
	dec.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("RC4 decryption loop failed or discard 1000 bytes did not roundtrip correctly")
	}
}

func TestTransformCallInstructions_Roundtrip(t *testing.T) {
	// E8 followed by displacement 0x00112200 (highest byte is 0x00, fits filter)
	// E9 followed by displacement 0xFF1122FF (highest byte is 0xFF, fits filter)
	originalBytes := []byte{
		0xE8, 0x00, 0x22, 0x11, 0x00, // CALL
		0x90,                         // NOP
		0xE9, 0xFF, 0x22, 0x11, 0xFF, // JMP
	}

	buf := make([]byte, len(originalBytes))
	copy(buf, originalBytes)

	// Transform (encode = true)
	TransformCallInstructions(buf, 0x1000, true)

	if bytes.Equal(buf, originalBytes) {
		t.Error("TransformCallInstructions failed to encode relative addresses (bytes remained identical)")
	}

	// Restore (encode = false)
	TransformCallInstructions(buf, 0x1000, false)

	if !bytes.Equal(buf, originalBytes) {
		t.Errorf("TransformCallInstructions restore failed: expected original bytes %v, got %v", originalBytes, buf)
	}
}

func TestTransformCallInstructions5309_Roundtrip(t *testing.T) {
	originalBytes := []byte{
		0xE8, 0x00, 0x22, 0x11, 0x00, // CALL
		0x90,                         // NOP
		0xE9, 0xFF, 0x22, 0x11, 0xFF, // JMP
	}

	buf := make([]byte, len(originalBytes))
	copy(buf, originalBytes)

	// Transform (encode = true)
	TransformCallInstructions5309(buf, 0x2000, true)

	if bytes.Equal(buf, originalBytes) {
		t.Error("TransformCallInstructions5309 failed to encode (bytes remained identical)")
	}

	// Restore (encode = false)
	TransformCallInstructions5309(buf, 0x2000, false)

	if !bytes.Equal(buf, originalBytes) {
		t.Errorf("TransformCallInstructions5309 restore failed: expected original bytes %v, got %v", originalBytes, buf)
	}
}
