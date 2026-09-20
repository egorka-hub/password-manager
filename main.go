package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	special = "!@#$%^&*()-_=+[]{}<>?"
	charset = upper + lower + digits + special
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return errors.New("password is too weak")
	}

	pm.masterKey = make([]byte, 32)
	copy(pm.masterKey, []byte(masterPassword))
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return errors.New("master password not set")
	}

	if _, exists := pm.passwords[name]; exists {
		return errors.New("password already exists")
	}

	pm.passwords[name] = NewPassword(name, value, category)

	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, errors.New("password manager not initialized")
	}
	if _, exists := pm.passwords[name]; !exists {
		return Password{}, errors.New("password not found")
	}
	return pm.passwords[name], nil
}

func (pm *PasswordManager) ListPasswords() []Password {
	pw := make([]Password, 0, len(pm.passwords))

	for _, password := range pm.passwords {
		pw = append(pw, password)
	}

	return pw
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New("password is too weak")
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	result := make([]byte, length)
	for i, b := range buf {
		result[i] = charset[int(b)%len(charset)]
	}

	return string(result), nil
}

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return errors.New("password manager not initialized")
	}

	plaintext, err := json.Marshal(pm.passwords)
	if err != nil {
		return errors.New("failed to marshal passwords")
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return errors.New("failed to create cipher")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("failed to create GCM")
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return errors.New("failed to generate nonce")
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return errors.New("failed to create file")
	}
	defer file.Close()

	if _, err := file.Write(nonce); err != nil {
		return errors.New("failed to write nonce to file")
	}

	if _, err := file.Write(ciphertext); err != nil {
		return errors.New("failed to write to file")
	}

	return nil
}

func main() {
	pm := NewPasswordManager("passwords.dat")

	if err := pm.SaveToFile(); err != nil {
		fmt.Println("Error saving passwords to file:", err)
	}

	if err := pm.SetMasterPassword("supersecret123"); err != nil {
		fmt.Println("Error setting master password:", err)
		return
	}

	if err := pm.SavePassword("gmail", "qwerty123", "email"); err != nil {
		fmt.Println("Error saving password:", err)
		return
	}

	if err := pm.SaveToFile(); err != nil {
		fmt.Println("Save after init:", err)
	} else {
		fmt.Println("Save after init: <nil>")
	}

}
