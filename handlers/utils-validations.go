package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"strings"
)

// GenerateVerificationToken gera um token único para verificação de email
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ValidateEmail verifica se o email está em um formato válido
func validateEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateUsername verifica se o username está em um formato válido
func validateUsername(username string) bool {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return usernameRegex.MatchString(username)
}

// ValidatePassword verifica se a senha atende aos requisitos mínimos
func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	// Pelo menos uma letra maiúscula
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	// Pelo menos uma letra minúscula
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	// Pelo menos um número
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	// Pelo menos um caractere especial
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	return hasUpper && hasLower && hasNumber && hasSpecial
}

//...
