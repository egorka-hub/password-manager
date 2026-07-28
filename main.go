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

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, fmt.Errorf("password manager not initialized")
	}
	p, exists := pm.passwords[name]
	if !exists {
		return Password{}, fmt.Errorf("password not found")
	}

	return p, nil
}

func main() {
	pm := NewPasswordManager("passwords.dat")

	_, uninitErr := pm.GetPassword("github.com")
	fmt.Printf("Get from uninitialized manager: %v\n", uninitErr)

	pm.SetMasterPassword("134234Staple")

	_, notFoundErr := pm.GetPassword("github.com")
	fmt.Printf("Get non-existent password: %v\n", notFoundErr)

	pm.SavePassword("github.com", "MyPassword123", "dev")

	found, _ := pm.GetPassword("github.com")
	fmt.Printf("Found password: %+v\n", found)
}
