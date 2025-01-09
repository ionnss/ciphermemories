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
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Invalid form data"}`)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Get and sanitize form values
	email := SanitizeInput(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	// Validate input
	if !ValidateEmail(email) {
		w.Header().Set("HX-Trigger", `{"showMessage": "Invalid email format"}`)
		http.Error(w, "Invalid email format", http.StatusBadRequest)
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
		w.Header().Set("HX-Trigger", `{"showMessage": "Invalid email or password"}`)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Invalid email or password"}`)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Check if email is verified
	if !user.VerifiedEmail {
		w.Header().Set("HX-Trigger", `{"showMessage": "Please verify your email before logging in"}`)
		http.Error(w, "Please verify your email before logging in", http.StatusUnauthorized)
		return
	}

	// Create session
	session, err := Store.Get(r, "session-ciphermemories")
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error creating session"}`)
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	// Set session values
	session.Values["authenticated"] = true
	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["last_activity"] = time.Now().Unix()

	fmt.Printf("Login: setting session values: %+v\n", session.Values)
	fmt.Printf("Login: session options: %+v\n", session.Options)

	// Save session
	if err := session.Save(r, w); err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error saving session"}`)
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Login successful for user ID: %d\n", user.ID)

	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// LogoutUser handles user logout
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: void
func LogoutUser(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "session-ciphermemories")
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error getting session"}`)
		http.Error(w, "Error getting session", http.StatusInternalServerError)
		return
	}

	// Limpa a sessão
	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})

	// Salva as alterações
	if err := session.Save(r, w); err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error saving session"}`)
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

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

// GetUserFromSession retorna o usuário da sessão atual
func GetUserFromSession(r *http.Request) *models.User {
	session, err := Store.Get(r, "session-ciphermemories")
	if err != nil {
		fmt.Printf("GetUserFromSession failed: error getting session: %v\n", err)
		fmt.Printf("Request cookies: %+v\n", r.Cookies())
		return nil
	}

	// Debug: print all session values
	fmt.Printf("Session values: %+v\n", session.Values)
	fmt.Printf("Session options: %+v\n", session.Options)

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		fmt.Printf("GetUserFromSession failed: could not convert user_id to int. Value: %v, Type: %T\n",
			session.Values["user_id"], session.Values["user_id"])
		return nil
	}

	fmt.Printf("GetUserFromSession: found userID: %d\n", userID)

	// Busca usuário no banco pelo ID
	user, err := GetUserByID(int64(userID))
	if err != nil {
		fmt.Printf("GetUserFromSession failed: error getting user from DB: %v\n", err)
		return nil
	}

	return user
}

// GetUserByUsername busca um usuário pelo username
func GetUserByUsername(username string) (*models.User, error) {
	var user models.User

	err := db.DB.QueryRow(`
		SELECT id, username, email, created_at, updated_at
		FROM users 
		WHERE username = $1
	`, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
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
		SELECT id, username, email, created_at, updated_at
		FROM users 
		WHERE id = $1
	`, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
