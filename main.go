package main

import (
	"fmt"
	"time"
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
		return fmt.Errorf("password is too weak")
	}
	pm.masterKey = make([]byte, 32)
	copy(pm.masterKey, masterPassword)
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager not initialized")
	}

	if _, exists := pm.passwords[name]; exists {
		return fmt.Errorf("password already exists")
	}

	newPassword := NewPassword(name, value, category)

	pm.passwords[name] = newPassword

	return nil
}

func main() {
	pm := NewPasswordManager("passwords.dat")

	uninitErr := pm.SavePassword("github.com", "secret123", "development")
	fmt.Printf("Save to uninitialized manager: %v\n", uninitErr)

	pm.SetMasterPassword("134234Staple")

	firstErr := pm.SavePassword("github.com", "secret123", "development")
	fmt.Printf("First save result: %v\n", firstErr)

	dupErr := pm.SavePassword("github.com", "anotherSecret", "development")
	fmt.Printf("Duplicate save result: %v\n", dupErr)
}
