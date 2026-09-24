package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	special = "!@#$%^&*()-_=+[]{}<>?"
	charset = upper + lower + digits + special
)

var (
	ErrNotInitialized   = errors.New("password manager not initialized")
	ErrPasswordExists   = errors.New("password already exists")
	ErrPasswordNotFound = errors.New("password not found")
	ErrWeakPassword     = errors.New("password is too weak")
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

type PasswordManager struct {
	passwords     map[string]Password
	masterKey     []byte
	filePath      string
	isInitialized bool
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
		return ErrWeakPassword
	}

	pm.masterKey = make([]byte, 32)
	copy(pm.masterKey, masterPassword)
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	if _, exists := pm.passwords[name]; exists {
		return ErrPasswordExists
	}

	pm.passwords[name] = NewPassword(name, value, category)

	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, ErrNotInitialized
	}
	if _, exists := pm.passwords[name]; !exists {
		return Password{}, ErrPasswordNotFound
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
		return "", ErrWeakPassword
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	result := make([]byte, length)
	for i, b := range buf {
		result[i] = charset[int(b)%len(charset)]
	}

	return string(result), nil
}

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

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune(special, r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrWeakPassword
	}
	return nil
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	passwords := make([]Password, 0)
	for _, password := range pm.passwords {
		if !strings.EqualFold(password.Category, category) {
			continue
		}
		passwords = append(passwords, password)
	}
	return passwords
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	byValue := make(map[string][]string)
	for _, password := range pm.passwords {
		byValue[password.Value] = append(byValue[password.Value], password.Name)
	}

	for value, services := range byValue {
		if len(services) < 2 {
			delete(byValue, value)
		}
	}

	return byValue
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	password, exists := pm.passwords[name]
	if !exists {
		return ErrPasswordNotFound
	}

	if err := pm.CheckPasswordStrength(newValue); err != nil {
		return err
	}

	password.Value = newValue
	password.LastModified = time.Now()
	pm.passwords[name] = password

	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	if _, exists := pm.passwords[name]; !exists {
		return ErrPasswordNotFound
	}

	delete(pm.passwords, name)

	return nil
}

func main() {
	pm := NewPasswordManager("passwords.dat")

	if err := pm.SetMasterPassword("mysecretpassword"); err != nil {
		log.Fatalf("set master password: %v", err)
	}

	if err := pm.SavePassword("gmail.com", "mynewpassword234324", "chat"); err != nil {
		log.Fatalf("save password: %v", err)
	}

	err := pm.DeletePassword("nonexistent.com")
	fmt.Printf("Deleting a nonexistent password: %v\n", err)

	err = pm.DeletePassword("gmail.com")
	fmt.Printf("Deleting an existing password: %v\n", err)

	fmt.Printf("Remaining number of passwords: %d\n", len(pm.ListPasswords()))

	_, err = pm.GetPassword("gmail.com")
	fmt.Printf("Attempt to get a deleted password: %v\n", err)
}
