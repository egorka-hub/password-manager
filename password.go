package main

import (
	"errors"
	"time"
)

// Errors returned by PasswordManager methods.
var (
	ErrNotInitialized   = errors.New("password manager not initialized")
	ErrPasswordExists   = errors.New("password already exists")
	ErrPasswordNotFound = errors.New("password not found")
	ErrWeakPassword     = errors.New("password is too weak")
)

// Password is a single stored credential.
type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

// NewPassword creates a Password with CreatedAt and LastModified set to now.
func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}
