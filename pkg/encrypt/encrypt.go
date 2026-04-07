package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	saltSize = 16
	keySize  = 32

	// KDF Bounds for DoS protection
	maxArgon2Time     = 10
	maxArgon2Memory   = 1024 * 1024 // 1 GiB
	maxArgon2Threads  = 32
	maxScryptN        = 1 << 20 // 1,048,576
	maxScryptR        = 32
	maxScryptP        = 32
)

// ZeroBytes clears the memory of a byte slice to prevent sensitive data 
// from persisting longer than necessary.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	fileMagic = []byte("SBK1") // Secure BacKup v1
)

type kdfID byte

const (
	kdfArgon2id kdfID = 1
	kdfScrypt   kdfID = 2
)

type argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

type scryptParams struct {
	N uint32
	R uint32
	P uint32
}

func getenvUint(key string, def uint32) uint32 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		return def
	}
	return uint32(n)
}

func getenvUint8(key string, def uint8) uint8 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil || n == 0 {
		return def
	}
	return uint8(n)
}

func selectedKDF() kdfID {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECURE_BACKUP_KDF"))) {
	case "", "argon2id", "argon2":
		return kdfArgon2id
	case "scrypt":
		return kdfScrypt
	default:
		// Default to Argon2id if unknown.
		return kdfArgon2id
	}
}

func deriveKey(password []byte, salt []byte, which kdfID, a argon2Params, s scryptParams) ([]byte, error) {
	switch which {
	case kdfArgon2id:
		key := argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, keySize)
		return key, nil
	case kdfScrypt:
		// scrypt params must satisfy library constraints; errors will be returned if invalid.
		key, err := scrypt.Key(password, salt, int(s.N), int(s.R), int(s.P), keySize)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported KDF")
	}
}

// EncryptData encrypts the given data using AES-GCM with a key derived from a password.
func EncryptData(plaintext []byte, password []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	which := selectedKDF()
	aParams := argon2Params{
		Time:    getenvUint("SECURE_BACKUP_ARGON2_TIME", 3),
		Memory:  getenvUint("SECURE_BACKUP_ARGON2_MEMORY_KIB", 64*1024), // 64 MiB
		Threads: getenvUint8("SECURE_BACKUP_ARGON2_THREADS", 1),
	}
	sParams := scryptParams{
		N: getenvUint("SECURE_BACKUP_SCRYPT_N", 1<<15), // 32768
		R: getenvUint("SECURE_BACKUP_SCRYPT_R", 8),
		P: getenvUint("SECURE_BACKUP_SCRYPT_P", 1),
	}

	key, err := deriveKey(password, salt, which, aParams, sParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Layout:
	// [4 bytes magic "SBK1"]
	// [1 byte kdf id]
	// [1 byte salt len][salt]
	// [kdf params...]
	// [nonce (12 bytes for AES-GCM)]
	// [ciphertext+tag]
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	var header []byte
	header = append(header, fileMagic...)
	header = append(header, byte(which))
	header = append(header, byte(len(salt)))
	header = append(header, salt...)

	switch which {
	case kdfArgon2id:
		buf := make([]byte, 4+4+1)
		binary.BigEndian.PutUint32(buf[0:4], aParams.Time)
		binary.BigEndian.PutUint32(buf[4:8], aParams.Memory)
		buf[8] = byte(aParams.Threads)
		header = append(header, buf...)
	case kdfScrypt:
		buf := make([]byte, 4+4+4)
		binary.BigEndian.PutUint32(buf[0:4], sParams.N)
		binary.BigEndian.PutUint32(buf[4:8], sParams.R)
		binary.BigEndian.PutUint32(buf[8:12], sParams.P)
		header = append(header, buf...)
	default:
		return nil, fmt.Errorf("unsupported KDF")
	}

	finalData := append(header, append(nonce, ciphertext...)...)

	return finalData, nil
}

// DecryptData decrypts the given data using a password.
func DecryptData(data []byte, password []byte) ([]byte, error) {
	// Refuse legacy (PBKDF2) format rather than silently guessing.
	if len(data) < 4 || string(data[:4]) != string(fileMagic) {
		return nil, fmt.Errorf("unsupported ciphertext format (legacy PBKDF2 payloads are not supported)")
	}

	remaining := data[4:]
	if len(remaining) < 1+1 {
		return nil, fmt.Errorf("ciphertext header too short")
	}

	which := kdfID(remaining[0])
	saltLen := int(remaining[1])
	remaining = remaining[2:]
	if saltLen <= 0 || saltLen > 64 || len(remaining) < saltLen {
		return nil, fmt.Errorf("invalid salt length")
	}
	salt := remaining[:saltLen]
	remaining = remaining[saltLen:]

	var aParams argon2Params
	var sParams scryptParams

	switch which {
	case kdfArgon2id:
		if len(remaining) < 9 {
			return nil, fmt.Errorf("ciphertext header too short for argon2 params")
		}
		aParams.Time = binary.BigEndian.Uint32(remaining[0:4])
		aParams.Memory = binary.BigEndian.Uint32(remaining[4:8])
		aParams.Threads = uint8(remaining[8])
		remaining = remaining[9:]
		// Strict bounds for DoS protection against malicious headers.
		if aParams.Time == 0 || aParams.Time > maxArgon2Time ||
			aParams.Memory == 0 || aParams.Memory > maxArgon2Memory ||
			aParams.Threads == 0 || aParams.Threads > maxArgon2Threads {
			return nil, fmt.Errorf("invalid or excessive argon2 parameters")
		}
	case kdfScrypt:
		if len(remaining) < 12 {
			return nil, fmt.Errorf("ciphertext header too short for scrypt params")
		}
		sParams.N = binary.BigEndian.Uint32(remaining[0:4])
		sParams.R = binary.BigEndian.Uint32(remaining[4:8])
		sParams.P = binary.BigEndian.Uint32(remaining[8:12])
		remaining = remaining[12:]

		// Strict bounds for DoS protection.
		if sParams.N == 0 || sParams.N > maxScryptN ||
			sParams.R == 0 || sParams.R > maxScryptR ||
			sParams.P == 0 || sParams.P > maxScryptP {
			return nil, fmt.Errorf("invalid or excessive scrypt parameters")
		}
	default:
		return nil, fmt.Errorf("unknown KDF id")
	}

	key, err := deriveKey(password, salt, which, aParams, sParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(remaining) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := remaining[:nonceSize], remaining[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
