package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	special = "!@#$%^&*()-_=+[]{}<>?"
	charset = upper + lower + digits + special
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
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

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func showSuccess(message string) {
	fmt.Println(colorGreen + "✓ Success: " + message + colorReset)
}

func showError(message string) {
	fmt.Println(colorRed + "✗ Error: " + message + colorReset)
}

func showInfo(message string) {
	fmt.Println(colorYellow + "→ Info: " + message + colorReset)
}

func waitForEnter() {
	fmt.Println("Press Enter to continue...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func ReadUserInput(prompt string) string {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	input, err := r.ReadString('\n')
	if err != nil {
		showError("Failed to read input")
		return ""
	}
	input = strings.TrimSpace(input)
	return input
}

func readPassword() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	result := string(password)
	return result, nil
}

func ShowMainMenu() {
	clearScreen()
	separator := strings.Repeat("=", 42)
	fmt.Println(separator)
	fmt.Println("             Password Manager             ")
	fmt.Println(separator)
	fmt.Println("1. Generate new password")
	fmt.Println("2. Add new password")
	fmt.Println("3. Get password")
	fmt.Println("4. List all passwords")
	fmt.Println("5. Update password")
	fmt.Println("6. Delete password")
	fmt.Println("7. List categories")
	fmt.Println("8. Show password statistics")
	fmt.Println("9. Find duplicate passwords")
	fmt.Println("0. Exit")
	fmt.Println(separator)
	fmt.Println()
}

func PrintPasswordList(passwords []Password) {
	format := "%-20s %-15s %-19s %s\n"
	separator := strings.Repeat("-", 80)

	fmt.Println("=== Password list ===")
	fmt.Printf(format, "Name", "Category", "Created", "Last Modified")
	fmt.Println(separator)
	for _, p := range passwords {
		fmt.Printf(format, p.Name, p.Category,
			p.CreatedAt.Format("2006-01-02"),
			p.LastModified.Format("2006-01-02"))
	}
	fmt.Println()
}

func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password Details ===")
	fmt.Printf("Service: %s\n", password.Name)
	fmt.Printf("Category: %s\n", password.Category)
	fmt.Printf("Password: %s\n", password.Value)
	fmt.Printf("Created: %s\n", password.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Modified: %s\n", password.LastModified.Format("2006-01-02 15:04:05"))
}

func HandlePasswordGeneration(pm *PasswordManager) error {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Password Generation ===")
	input := ReadUserInput("Enter password length (min 8): ")
	length, err := strconv.Atoi(input)
	if err != nil {
		showError("Length must be a whole number")
		return err
	}
	p, err := pm.GeneratePassword(length)
	if err != nil {
		if errors.Is(err, ErrWeakPassword) {
			showError("Length must be at least 8")
		} else {
			showError("Failed to generate password")
		}
		return err
	}
	showSuccess("Password generated successfully")
	fmt.Println("Generated password:", p)
	return nil
}

func HandlePasswordAdd(pm *PasswordManager) error {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Add New Password ===")
	input := ReadUserInput("Enter service name: ")
	if input == "" {
		showError("Service name cannot be empty")
		return nil
	}

	fmt.Print("Enter password (or press Enter to generate): ")
	value, err := readPassword()
	if err != nil {
		showError("Failed to read password")
		return err
	}
	if value == "" {
		value, err = pm.GeneratePassword(16)
		if err != nil {
			showError("Failed to generate password")
			return err
		}
		showInfo("Generated password: " + value)
	}

	category := ReadUserInput("Enter category: ")

	if err = pm.SavePassword(input, value, category); err != nil {
		if errors.Is(err, ErrPasswordExists) {
			showError("Password for " + input + " already exists, use update instead")
		} else if errors.Is(err, ErrNotInitialized) {
			showError("Password manager is not initialized")
		} else {
			showError("Failed to save password")
		}
		return err
	}
	showSuccess("Password saved successfully")
	return nil
}

func HandlePasswordSearch(pm *PasswordManager) error {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Search Password ===")
	input := ReadUserInput("Enter service name: ")
	if input == "" {
		showError("Service name cannot be empty")
		return nil
	}

	password, err := pm.GetPassword(input)
	if err != nil {
		if errors.Is(err, ErrPasswordNotFound) {
			showError("Password for " + input + " not found")
		} else if errors.Is(err, ErrNotInitialized) {
			showError("Password manager is not initialized")
		} else {
			showError("Failed to get password")
		}
		return err
	}
	ShowPasswordDetails(password)
	return nil
}
func HandlePasswordUpdate(pm *PasswordManager) error {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Update Password ===")
	input := ReadUserInput("Enter service name: ")
	if input == "" {
		showError("Service name cannot be empty")
		return nil
	}
	fmt.Print("Enter new password: ")
	newValue, err := readPassword()
	if err != nil {
		showError("Failed to read password")
		return err
	}
	err = pm.UpdatePassword(input, newValue)
	if err != nil {
		if errors.Is(err, ErrNotInitialized) {
			showError("Password manager is not initialized")
		} else if errors.Is(err, ErrWeakPassword) {
			showError("Password is too weak (min 8 chars, upper, lower, digit, special)")
		} else if errors.Is(err, ErrPasswordNotFound) {
			showError("Password for " + input + " not found")
		} else {
			showError("Failed to update password")
		}
		return err
	}
	showSuccess("Password updated successfully")
	return nil
}

func HandleExitAndSave(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Saving and Exiting ===")
	fmt.Println("Saving changes...")
	err := pm.SaveToFile()
	if err != nil {
		wrapped := fmt.Errorf("error saving data: %w", err)
		showError(wrapped.Error())
		return wrapped
	}
	showSuccess("Changes saved successfully!")
	showSuccess("Goodbye!")
	return nil
}

func main() {

}
