package main

import (
	"crypto/rand"
	"fmt"
	"sort"
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

// PasswordManager keeps passwords in memory and persists them to an
// encrypted file. It must be unlocked with SetMasterPassword before use.
type PasswordManager struct {
	passwords     map[string]Password
	masterKey     []byte
	filePath      string
	isInitialized bool
}

// NewPasswordManager returns an empty, locked manager bound to filePath.
func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		filePath:      filePath,
		isInitialized: false,
	}
}

// SetMasterPassword derives the encryption key from masterPassword and
// unlocks the manager. It returns ErrWeakPassword if the password is
// shorter than 8 characters.
func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return ErrWeakPassword
	}

	pm.masterKey = make([]byte, 32)
	copy(pm.masterKey, masterPassword)
	pm.isInitialized = true

	return nil
}

// SavePassword adds a new password. It returns ErrPasswordExists if a
// password with the same name is already stored.
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

// GetPassword returns the password stored under name, or
// ErrPasswordNotFound if there is none.
func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, ErrNotInitialized
	}
	if _, exists := pm.passwords[name]; !exists {
		return Password{}, ErrPasswordNotFound
	}
	return pm.passwords[name], nil
}

// ListPasswords returns all stored passwords in no particular order.
func (pm *PasswordManager) ListPasswords() []Password {
	pw := make([]Password, 0, len(pm.passwords))

	for _, password := range pm.passwords {
		pw = append(pw, password)
	}

	return pw
}

// GeneratePassword returns a random password of the given length built
// from upper- and lowercase letters, digits and special characters.
// It returns ErrWeakPassword if length is less than 8.
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

// CheckPasswordStrength returns ErrWeakPassword unless password has at
// least 8 characters and contains an uppercase letter, a lowercase
// letter, a digit and a special character.
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

// GetPasswordsByCategory returns passwords whose category matches
// category, ignoring case.
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

// FindDuplicatePasswords groups service names that share the same
// password value. The map is keyed by the password value itself, so keys
// must not be displayed.
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

// UpdatePassword replaces the value of an existing password after
// checking its strength with CheckPasswordStrength.
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

// DeletePassword removes the password stored under name.
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

// ListCategories returns the unique categories in lowercase, sorted
// alphabetically.
func (pm *PasswordManager) ListCategories() []string {
	unique := make(map[string]bool)
	for _, p := range pm.passwords {
		unique[strings.ToLower(p.Category)] = true
	}

	categories := make([]string, 0, len(unique))
	for c := range unique {
		categories = append(categories, c)
	}

	sort.Strings(categories)

	return categories
}

// GetPasswordStats returns totalPasswords (int), categories ([]string),
// categoryCounts (map[string]int), newestPassword and oldestPassword
// (time.Time).
func (pm *PasswordManager) GetPasswordStats() map[string]any {
	var newest, oldest time.Time
	categoryCounts := make(map[string]int)

	for _, p := range pm.passwords {
		categoryCounts[strings.ToLower(p.Category)]++

		if p.CreatedAt.After(newest) {
			newest = p.CreatedAt
		}

		if oldest.IsZero() || p.CreatedAt.Before(oldest) {
			oldest = p.CreatedAt
		}
	}

	return map[string]any{
		"totalPasswords": len(pm.passwords),
		"categories":     pm.ListCategories(),
		"categoryCounts": categoryCounts,
		"newestPassword": newest,
		"oldestPassword": oldest,
	}
}
