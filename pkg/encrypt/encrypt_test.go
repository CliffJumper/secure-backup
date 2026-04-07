package encrypt

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	content := []byte("hello world, this is a secret message!")
	password := []byte("very-secret-password")

	ciphertext, err := EncryptData(content, password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := DecryptData(ciphertext, password)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != string(content) {
		t.Errorf("Expected %s, got %s", content, plaintext)
	}
}
