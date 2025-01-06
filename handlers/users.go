package handlers

import (
	"ciphermemories/db"
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
type LoginResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	RedirectURL string `json:"redirect_url"`
}

// LoginUser handles user login
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: void
func LoginUser(w http.ResponseWriter, r *http.Request) {
	// Set response header
	w.Header().Set("Content-Type", "application/json")

	// Only allow POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Invalid form data",
		})
		return
	}

	// Get and sanitize form values
	email := SanitizeInput(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	// Validate input
	if !validateEmail(email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Invalid email format",
		})
		return
	}

	// Get user from database
	var user struct {
		ID             int
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
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Check if email is verified
	if !user.VerifiedEmail {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Please verify your email before logging in",
		})
		return
	}

	// Create session
	session, err := Store.Get(r, "session-name")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Error creating session",
		})
		return
	}

	// Set session values
	session.Values["authenticated"] = true
	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["last_activity"] = time.Now().Unix()

	// Save session
	if err := session.Save(r, w); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(LoginResponse{
			Success: false,
			Message: "Error saving session",
		})
		return
	}

	// Return success with redirect URL
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{
		Success:     true,
		Message:     "Login successful",
		RedirectURL: "/dashboard",
	})
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
