package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// SaveToFile encrypts all passwords with AES-256-GCM and writes them to
// the manager's file as nonce followed by ciphertext.
func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	plaintext, err := json.Marshal(pm.passwords)
	if err != nil {
		return fmt.Errorf("marshal passwords: %w", err)
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return fmt.Errorf("create %s: %w", pm.filePath, err)
	}
	defer file.Close()

	if _, err := file.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}

	if _, err := file.Write(ciphertext); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}

	return nil
}

// LoadFromFile reads and decrypts the manager's file. If the file does
// not exist, the returned error wraps os.ErrNotExist.
func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	file, err := os.Open(pm.filePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", pm.filePath, err)
	}
	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(file, nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", pm.filePath, err)
	}

	decryptedData, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	err = json.Unmarshal(decryptedData, &pm.passwords)
	if err != nil {
		return fmt.Errorf("unmarshal passwords: %w", err)
	}

	return nil
}
