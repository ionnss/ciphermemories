package handlers

import (
	"ciphermemories/db"
	"ciphermemories/models"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RegisterUser handles user registration
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: void
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
	email := SanitizeInput(strings.TrimSpace(strings.ToLower(r.FormValue("email"))))
	username := SanitizeInput(strings.TrimSpace(r.FormValue("username")))
	password := r.FormValue("password")

	// Validate input
	if !ValidateEmail(email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Invalid email format",
		})
		return
	}

	if !ValidateUsername(username) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RegisterResponse{
			Success: false,
			Message: "Invalid username format. Use only letters, numbers, underscore, and hyphen (3-30 characters)",
		})
		return
	}

	if !ValidatePassword(password) {
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
	verificationToken, err := GenerateVerificationToken()
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
		INSERT INTO users (email, username, hashed_password, verification_token, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
	`, email, username, string(hashedPassword), verificationToken, "/static/assets/default-avatar.png")

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			w.WriteHeader(http.StatusConflict)
			message := "Email already registered"
			if strings.Contains(err.Error(), "users_username_key") {
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

// VerifyEmail verifies the user's email
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: void
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

// LoginUser handles user login
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: void
func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		fmt.Printf("[ERROR] Failed to parse login form\n")
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := SanitizeInput(strings.ToLower(r.FormValue("email")))

	// Get user from database
	var user struct {
		ID             int64
		Username       string
		HashedPassword string
		VerifiedEmail  bool
	}

	err := db.DB.QueryRow(`
		SELECT id, username, hashed_password, verified_email 
		FROM users 
		WHERE email = $1
	`, email).Scan(&user.ID, &user.Username, &user.HashedPassword, &user.VerifiedEmail)

	if err != nil {
		fmt.Printf("[INFO] Login attempt failed: invalid credentials\n")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(r.FormValue("password"))); err != nil {
		fmt.Printf("[INFO] Login attempt failed: invalid credentials\n")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if !user.VerifiedEmail {
		fmt.Printf("[INFO] Login attempt failed: email not verified\n")
		http.Error(w, "Please verify your email before logging in", http.StatusUnauthorized)
		return
	}

	// Clear any existing session
	ClearSession(w, r)

	// Create new session
	if err := CreateSession(w, r, user.ID, user.Username); err != nil {
		fmt.Printf("[ERROR] Failed to create session\n")
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[INFO] Login successful\n")

	// Set secure headers
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Redirect to dashboard
	w.Header().Set("Location", "/dashboard")
	w.WriteHeader(http.StatusFound)
}

// LogoutUser handles user logout
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: void
func LogoutUser(w http.ResponseWriter, r *http.Request) {
	// Clear the session and all related cookies
	ClearSession(w, r)

	// Redirect to index
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "templates/forgot-password.html")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := SanitizeInput(strings.ToLower(r.FormValue("email")))
	if !ValidateEmail(email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var userID int64
	err := db.DB.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	if err != nil {
		// Don't reveal if email exists or not
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<div class="alert alert-success">If your email is registered, you will receive a password reset link shortly.</div>`)
		return
	}

	// Generate reset token
	token, err := GenerateVerificationToken()
	if err != nil {
		http.Error(w, "Error generating reset token", http.StatusInternalServerError)
		return
	}

	// Store token in database with expiration
	expiresAt := time.Now().Add(15 * time.Minute)
	_, err = db.DB.Exec(`
		INSERT INTO password_reset_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, userID, token, expiresAt)

	if err != nil {
		http.Error(w, "Error processing request", http.StatusInternalServerError)
		return
	}

	// Send reset email
	resetURL := fmt.Sprintf("https://ciphermemories.com/reset-password?token=%s", token)
	emailData := &EmailData{
		Title:      "Reset Your Password - Cipher Memories",
		Message:    "Click the button below to reset your password. This link will expire in 15 minutes.",
		ButtonText: "Reset Password",
		ButtonURL:  resetURL,
	}

	if err := SendEmail(email, "Reset Your Password - Cipher Memories", emailData); err != nil {
		fmt.Printf("Error sending reset email: %v\n", err)
		http.Error(w, "Error sending reset email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<div class="alert alert-success">If your email is registered, you will receive a password reset link shortly.</div>`)
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if token exists and is valid
		var expiresAt time.Time
		var used bool
		err := db.DB.QueryRow(`
			SELECT expires_at, used 
			FROM password_reset_tokens 
			WHERE token = $1
		`, token).Scan(&expiresAt, &used)

		if err != nil || time.Now().After(expiresAt) || used {
			http.Redirect(w, r, "/?error=invalid_token", http.StatusSeeOther)
			return
		}

		// Redirect to index with token and show modal
		http.Redirect(w, r, fmt.Sprintf("/?reset_token=%s", token), http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")

	if !ValidatePassword(password) {
		http.Error(w, "Password must be at least 8 characters long and contain uppercase, lowercase, number and special character", http.StatusBadRequest)
		return
	}

	// Get user ID from token
	var userID int64
	var expiresAt time.Time
	var used bool
	err := db.DB.QueryRow(`
		SELECT user_id, expires_at, used 
		FROM password_reset_tokens 
		WHERE token = $1
	`, token).Scan(&userID, &expiresAt, &used)

	if err != nil || time.Now().After(expiresAt) || used {
		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	// Start transaction
	tx, err := db.DB.Begin()
	if err != nil {
		http.Error(w, "Error processing request", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	// Update password
	_, err = tx.Exec(`
		UPDATE users 
		SET hashed_password = $1, 
		    updated_at = CURRENT_TIMESTAMP 
		WHERE id = $2
	`, string(hashedPassword), userID)

	if err != nil {
		http.Error(w, "Error updating password", http.StatusInternalServerError)
		return
	}

	// Mark token as used
	_, err = tx.Exec(`
		UPDATE password_reset_tokens 
		SET used = true 
		WHERE token = $1
	`, token)

	if err != nil {
		http.Error(w, "Error updating token", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		http.Error(w, "Error completing password reset", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<div class="alert alert-success">Password reset successful! Please login with your new password. Redirecting...</div>`)
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

// GetUserByUsername busca um usuário pelo username
func GetUserByUsername(username string) (*models.User, error) {
	var user models.User

	err := db.DB.QueryRow(`
		SELECT id, username, email, COALESCE(avatar_url, '/static/assets/default-avatar.png') as avatar_url, created_at, updated_at
		FROM users 
		WHERE username = $1
	`, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func GetUserByID(userID int64) (*models.User, error) {
	var user models.User

	err := db.DB.QueryRow(`
		SELECT id, username, email, COALESCE(avatar_url, '/static/assets/default-avatar.png') as avatar_url, created_at, updated_at
		FROM users 
		WHERE id = $1
	`, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
