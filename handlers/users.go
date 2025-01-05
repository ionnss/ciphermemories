package handlers

import (
	"ciphermemories/db"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	// Set response header
	w.Header().Set("Content-Type", "application/json")

	// Only allow POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Invalid form data",
		})
		return
	}

	// Get form values
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Validate input
	if !validateEmail(email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Invalid email format",
		})
		return
	}

	if !validateUsername(username) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Invalid username format. Use only letters, numbers, underscore, and hyphen (3-30 characters)",
		})
		return
	}

	if !validatePassword(password) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Password must be at least 8 characters long and contain uppercase, lowercase, number and special character",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Error processing registration",
		})
		return
	}

	// Generate verification token
	verificationToken, err := generateVerificationToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Error processing registration",
		})
		return
	}

	// Insert user into database
	_, err = db.DB.Exec(`
		INSERT INTO users (email, username, hashed_password, verification_token)
		VALUES ($1, $2, $3, $4)
	`, email, username, string(hashedPassword), verificationToken)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			w.WriteHeader(http.StatusConflict)
			message := "Email already registered"
			if strings.Contains(err.Error(), "idx_username") {
				message = "Username already taken"
			}
			json.NewEncoder(w).Encode(RegisterResponse{
				Success: false,
				Message: message,
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Error processing registration",
		})
		return
	}

	// Send verification email
	verificationURL := fmt.Sprintf("https://ciphermemories.com/verify?token=%s", verificationToken)

	emailData := &EmailData{
		Title:      "Welcome to Cipher Memories - Verify Your Email",
		Message:    fmt.Sprintf("Welcome %s! Please verify your email address to complete your registration.", username),
		ButtonText: "Verify Email",
		ButtonURL:  verificationURL,
	}

	if err := SendEmail(email, "Verify Your Email - Cipher Memories", emailData); err != nil {
		// Log the error but don't return it to the user
		fmt.Printf("Error sending verification email: %v\n", err)
	}

	// Return success response
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{
		Success: true,
		Message: "Registration successful. Please check your email to verify your account.",
	})
}

func VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Get token from query params
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/?error=missing_token", http.StatusSeeOther)
		return
	}

	// Update user verification status
	result, err := db.DB.Exec(`
		UPDATE users 
		SET verified_email = true, 
			verification_token = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE verification_token = $1 
		AND verified_email = false
	`, token)

	if err != nil {
		http.Redirect(w, r, "/?error=server_error", http.StatusSeeOther)
		return
	}

	// Check if any row was affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Redirect(w, r, "/?error=server_error", http.StatusSeeOther)
		return
	}

	if rowsAffected == 0 {
		http.Redirect(w, r, "/?error=invalid_token", http.StatusSeeOther)
		return
	}

	// Redirect to index with success message
	http.Redirect(w, r, "/?verified=true", http.StatusSeeOther)
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement login
}

func LogoutUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement logout
}

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement forgot password
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement reset password
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement update user
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement delete user
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get user
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement get users
}
