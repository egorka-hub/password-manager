package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HandlePasswordGeneration asks for a length and prints a generated password.
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

// HandlePasswordAdd asks for a service, password and category and saves
// them. An empty password is replaced with a generated one.
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

// HandlePasswordSearch asks for a service name and shows its details.
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

// HandlePasswordUpdate asks for a service name and a new password and
// updates it.
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

// HandleExitAndSave saves all passwords to the file before exit.
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

// HandlePasswordList prints all passwords sorted by name.
func HandlePasswordList(pm *PasswordManager) {
	clearScreen()
	defer waitForEnter()
	passwords := pm.ListPasswords()
	if len(passwords) == 0 {
		showInfo("No passwords saved yet")
		return
	}
	sort.Slice(passwords, func(i, j int) bool {
		return strings.ToLower(passwords[i].Name) < strings.ToLower(passwords[j].Name)
	})
	PrintPasswordList(passwords)
}

// HandlePasswordDelete asks for a service name and deletes it after
// confirmation.
func HandlePasswordDelete(pm *PasswordManager) {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Delete Password ===")
	input := ReadUserInput("Enter service name: ")
	if input == "" {
		showError("Service name cannot be empty")
		return
	}
	if _, err := pm.GetPassword(input); err != nil {
		if errors.Is(err, ErrPasswordNotFound) {
			showError("Password for " + input + " not found")
		} else if errors.Is(err, ErrNotInitialized) {
			showError("Password manager is not initialized")
		} else {
			showError("Failed to get password")
		}
		return
	}
	confirm := ReadUserInput("Delete " + input + "? (y/n): ")
	if strings.ToLower(confirm) != "y" {
		showInfo("Deletion cancelled")
		return
	}
	if err := pm.DeletePassword(input); err != nil {
		showError("Failed to delete password")
		return
	}
	showSuccess("Password deleted successfully!")
}

// HandleCategoryList prints all categories.
func HandleCategoryList(pm *PasswordManager) {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Categories ===")
	list := pm.ListCategories()
	if len(list) == 0 {
		showInfo("No categories yet")
		return
	}
	for _, category := range list {
		if category == "" {
			fmt.Println("- (no category)")
			continue
		}
		fmt.Println("- " + category)
	}
}

// HandlePasswordStats prints password counts per category and the
// creation dates of the newest and oldest passwords.
func HandlePasswordStats(pm *PasswordManager) {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Password Statistics ===")
	stats := pm.GetPasswordStats()
	total, ok1 := stats["totalPasswords"].(int)
	categories, ok2 := stats["categories"].([]string)
	counts, ok3 := stats["categoryCounts"].(map[string]int)
	newest, ok4 := stats["newestPassword"].(time.Time)
	oldest, ok5 := stats["oldestPassword"].(time.Time)

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		showError("Failed to read statistics")
		return
	}
	if total == 0 {
		showInfo("No passwords saved yet")
		return
	}
	fmt.Println("Total passwords: " + strconv.Itoa(total))
	fmt.Println("Categories: " + strconv.Itoa(len(categories)))
	for _, category := range categories {
		if category == "" {
			fmt.Println("- (no category): " + strconv.Itoa(counts[category]))
			continue
		}
		fmt.Println("- " + category + ": " + strconv.Itoa(counts[category]))
	}
	fmt.Println("Newest password: " + newest.Format("2006-01-02 15:04:05"))
	fmt.Println("Oldest password: " + oldest.Format("2006-01-02 15:04:05"))
}

// HandleDuplicatePasswords prints groups of services that share the same
// password without revealing the password.
func HandleDuplicatePasswords(pm *PasswordManager) {
	clearScreen()
	defer waitForEnter()
	fmt.Println("=== Duplicate Passwords ===")
	duplicates := pm.FindDuplicatePasswords()
	if len(duplicates) == 0 {
		showSuccess("No duplicate passwords found")
		return
	}
	showInfo(fmt.Sprintf("Found %d groups of services sharing the same password", len(duplicates)))
	for _, services := range duplicates {
		sort.Strings(services)
		fmt.Println("- " + strings.Join(services, ", "))
	}
	showInfo("Use unique passwords for each service")
}
