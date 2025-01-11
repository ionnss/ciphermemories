package handlers

import (
	"ciphermemories/db"
	"ciphermemories/models"
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
