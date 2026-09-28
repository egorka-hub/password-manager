package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

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

// ReadUserInput prints prompt and returns one line of input without
// surrounding whitespace.
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

// ShowMainMenu clears the screen and prints the main menu.
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

// PrintPasswordList prints passwords as a table without their values.
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

// ShowPasswordDetails prints all fields of password, including its value.
func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password Details ===")
	fmt.Printf("Service: %s\n", password.Name)
	fmt.Printf("Category: %s\n", password.Category)
	fmt.Printf("Password: %s\n", password.Value)
	fmt.Printf("Created: %s\n", password.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Modified: %s\n", password.LastModified.Format("2006-01-02 15:04:05"))
}
