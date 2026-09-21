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
	"sort"
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

func main() {
	pm := NewPasswordManager("passwords.dat")

	err := pm.SetMasterPassword("password49442")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = pm.SavePassword("github.com", "username", "dev")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = pm.SavePassword("gmail.com", "username2", "email")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = pm.SaveToFile()
	if err != nil {
		fmt.Println(err)
		return
	}

	pm2 := NewPasswordManager("passwords.dat")

	err = pm2.SetMasterPassword("password49442")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = pm2.LoadFromFile()
	if err != nil {
		fmt.Println(err)
		return
	}

	list := pm2.ListPasswords()

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	fmt.Printf("Loaded passwords: %d\n", len(list))

	for _, p := range list {
		fmt.Printf("Service: %s\tCategory: %s\n", p.Name, p.Category)
	}
}
