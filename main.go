// Command password-manager is a console password manager that keeps
// credentials in a local file encrypted with AES-256-GCM.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	clearScreen()
	fmt.Println("=== Password Manager Initialization ===")
	pm := NewPasswordManager("passwords.dat")

	fmt.Print("Enter master password: ")
	password, err := readPassword()
	if err != nil {
		showError("Error reading password")
		return
	}

	err = pm.SetMasterPassword(password)
	if err != nil {
		if errors.Is(err, ErrWeakPassword) {
			showError("Master password is too weak (min 8 chars)")
		} else {
			showError("Failed to set master password")
		}
		return
	}

	err = pm.LoadFromFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			showInfo("No saved passwords found, starting with an empty vault")
		} else {
			showError("Error loading data: " + err.Error())
			return
		}
	}
	showSuccess("Password manager initialized successfully")
	waitForEnter()

	for {
		ShowMainMenu()
		choice := ReadUserInput("Enter your choice: ")
		switch choice {
		case "0":
			err = HandleExitAndSave(pm)
			if err != nil {
				os.Exit(1)
			}
			return
		case "1":
			HandlePasswordGeneration(pm)
		case "2":
			HandlePasswordAdd(pm)
		case "3":
			HandlePasswordSearch(pm)
		case "4":
			HandlePasswordList(pm)
		case "5":
			HandlePasswordUpdate(pm)
		case "6":
			HandlePasswordDelete(pm)
		case "7":
			HandleCategoryList(pm)
		case "8":
			HandlePasswordStats(pm)
		case "9":
			HandleDuplicatePasswords(pm)
		default:
			showError("Invalid choice")
			waitForEnter()
		}

	}
}
