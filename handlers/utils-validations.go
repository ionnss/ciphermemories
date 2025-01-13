package handlers

import (
	"ciphermemories/db"
	"ciphermemories/models"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

// Store é a sessão do usuário
var Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

// init is a function that runs when the package is initialized
//
// returns: error
func init() {
	// Verifica se a chave da sessão está definida
	if os.Getenv("SESSION_KEY") == "" {
		panic("SESSION_KEY environment variable is not set")
	}

	fmt.Printf("Session store initialized with key length: %d\n", len(os.Getenv("SESSION_KEY")))

	// Get initial cookie domain from env
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	if strings.Contains(os.Getenv("HOST"), "localhost") ||
		strings.Contains(os.Getenv("HOST"), "127.0.0.1") {
		cookieDomain = "" // Empty domain for localhost
	}
	fmt.Printf("Initial cookie domain from env: %s\n", cookieDomain)

	// Configure store options
	Store.Options = &sessions.Options{
		Path:     "/",
		Domain:   cookieDomain,
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	fmt.Printf("Cookie store initialized with options: %+v\n", Store.Options)
}

// ClearSession limpa a sessão atual e seus cookies relacionados
func ClearSession(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, "session-ciphermemories")
	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})

	if err := session.Save(r, w); err != nil {
		fmt.Printf("[ERROR] Failed to clear session\n")
		return
	}

	fmt.Printf("[INFO] Session cleared\n")
}

// CreateSession cria uma nova sessão com os valores apropriados
func CreateSession(w http.ResponseWriter, r *http.Request, userID int64, username string) error {
	session, _ := Store.Get(r, "session-ciphermemories")
	session.Values = make(map[interface{}]interface{})

	// Set session values
	session.Values["authenticated"] = true
	session.Values["user_id"] = userID
	session.Values["username"] = username
	session.Values["version"] = os.Getenv("APP_VERSION")
	session.Values["created_at"] = time.Now().Unix()
	session.Values["last_activity"] = time.Now().Unix()

	// Set cookie options
	isLocalhost := strings.Contains(r.Host, "localhost") || strings.Contains(r.Host, "127.0.0.1")
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	if isLocalhost {
		cookieDomain = ""
	}

	session.Options = &sessions.Options{
		Path:     "/",
		Domain:   cookieDomain,
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	err := session.Save(r, w)
	if err != nil {
		fmt.Printf("[ERROR] Failed to create session\n")
		return err
	}

	fmt.Printf("[INFO] Session created successfully\n")
	return nil
}

// LogSessionIssue registra problemas com a sessão
func LogSessionIssue(r *http.Request, issue string) {
	userID := "unknown"
	if session, err := Store.Get(r, "session-ciphermemories"); err == nil {
		if id, ok := session.Values["user_id"].(int64); ok {
			userID = fmt.Sprintf("%d", id)
		}
	}

	fmt.Printf("Session issue: %s, User: %s, Time: %s\n",
		issue, userID, time.Now().Format(time.RFC3339))
}

// ValidateSession verifica se a sessão é válida
func ValidateSession(w http.ResponseWriter, r *http.Request) bool {
	session, err := Store.Get(r, "session-ciphermemories")
	if err != nil {
		fmt.Printf("[ERROR] Session validation failed\n")
		return false
	}

	sessionVersion, ok := session.Values["version"].(string)
	envVersion := os.Getenv("APP_VERSION")

	if !ok || sessionVersion != envVersion {
		fmt.Printf("[INFO] Session version check failed\n")
		ClearSession(w, r)
		return false
	}

	// Check session age
	if created, ok := session.Values["created_at"].(int64); ok {
		if time.Now().Unix()-created > 7*24*60*60 {
			fmt.Printf("[INFO] Session expired (age)\n")
			ClearSession(w, r)
			return false
		}
	}

	// Check last activity
	if lastActivity, ok := session.Values["last_activity"].(int64); ok {
		if time.Now().Unix()-lastActivity > 3600 {
			fmt.Printf("[INFO] Session expired (inactivity)\n")
			ClearSession(w, r)
			return false
		}
	}

	return true
}

// AuthHandler verifies if the user is authenticated
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: error
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if !ValidateSession(w, r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	session, _ := Store.Get(r, "session-ciphermemories")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

// AuthMiddleware protects routes that need authentication
//
// receives: next http.Handler
//
// returns: http.Handler
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ValidateSession(w, r) {
			if r.Header.Get("HX-Request") == "true" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				w.Header().Set("Cache-Control", "no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		session, _ := Store.Get(r, "session-ciphermemories")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			if r.Header.Get("HX-Request") == "true" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				w.Header().Set("Cache-Control", "no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		// Atualiza o último acesso
		session.Values["last_activity"] = time.Now().Unix()
		session.Save(r, w)

		next.ServeHTTP(w, r)
	})
}

// GenerateVerificationToken generates a unique token for email verification
//
// returns: token, error
func GenerateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ValidateEmail verifies if the email is in a valid format
//
// receives: email string
//
// returns: true if email is valid, false otherwise
func ValidateEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateUsername verifies if the username is in a valid format
//
// receives: username string
//
// returns: true if username is valid, false otherwise
func ValidateUsername(username string) bool {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return usernameRegex.MatchString(username)
}

// ValidatePassword verifies if the password meets the minimum requirements
//
// receives: password string
//
// returns: true if password is valid, false otherwise
func ValidatePassword(password string) bool {
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

// SanitizeInput removes dangerous characters from a string
//
// receives: input string
//
// returns: sanitized string
func SanitizeInput(input string) string {
	// Remove extra spaces
	input = strings.TrimSpace(input)

	// Remove caracteres de controle
	input = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(input, "")

	return input
}

// SecurityMiddleware adds security headers to all responses
//
// receives: next http.Handler
//
// returns: http.Handler
func SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevents Clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevents MIME-sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Enables XSS protection in the browser
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Forces HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; "+
				"img-src 'self' data: https:; "+
				"font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com https://cdnjs.cloudflare.com; "+
				"connect-src 'self';")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy (anteriormente Feature-Policy)
		w.Header().Set("Permissions-Policy",
			"camera=(), "+
				"microphone=(), "+
				"geolocation=(), "+
				"payment=()")

		next.ServeHTTP(w, r)
	})
}

// HTMXMiddleware verifies if the request is via HTMX
//
// receives: next http.Handler
//
// returns: http.Handler
func HTMXMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check GET requests for HTMX routes
		if r.Method == http.MethodGet && r.Header.Get("HX-Request") != "true" && isHTMXOnlyRoute(r.URL.Path) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isHTMXOnlyRoute verifies if the route should be accessed only via HTMX
//
// receives: path string
//
// returns: true if the route should be accessed only via HTMX, false otherwise
func isHTMXOnlyRoute(path string) bool {
	htmxOnlyRoutes := []string{
		"/login",
		"/register",
		"/terms",
		"/privacy",
	}

	for _, route := range htmxOnlyRoutes {
		if route == path {
			return true
		}
	}
	return false
}

// UserAvatarUpload handles user avatar uploads to local storage
func UserAvatarUpload(file io.Reader, userID int64, oldAvatarURL string) (string, error) {
	fmt.Printf("UserAvatarUpload: starting upload for user %d\n", userID)

	// Create uploads directory if it doesn't exist
	uploadsDir := "static/uploads/avatars"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create uploads directory: %v", err)
	}

	// Delete old avatar if it exists and is not the default avatar
	if oldAvatarURL != "" && !strings.Contains(oldAvatarURL, "default-avatar") {
		oldPath := strings.TrimPrefix(oldAvatarURL, "/")
		if err := os.Remove(oldPath); err != nil {
			fmt.Printf("Warning: Failed to delete old avatar: %v\n", err)
			// Continue with upload even if delete fails
		}
	}

	// Generate unique filename using UUID
	filename := fmt.Sprintf("%s.jpg", uuid.New().String())
	filepath := fmt.Sprintf("%s/%s", uploadsDir, filename)

	// Create new file
	newFile, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %v", err)
	}
	defer newFile.Close()

	// Copy uploaded file to new file
	if _, err := io.Copy(newFile, file); err != nil {
		return "", fmt.Errorf("failed to save file: %v", err)
	}

	// Return the URL path that will be stored in the database
	avatarURL := fmt.Sprintf("/%s/%s", uploadsDir, filename)
	fmt.Printf("UserAvatarUpload: upload successful - Path: %s\n", avatarURL)

	return avatarURL, nil
}

// GenerateRandomKey generates a random key
//
// returns: key, error
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}

// GenerateIV generates a random IV of 12 bytes
//
// returns: IV, error
func GenerateIV() ([]byte, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	return iv, nil
}

// EncryptContent encrypts the content using AES-GCM
//
// receives: content string, key []byte, iv []byte
//
// returns: encrypted content, tag, error
func EncryptContent(content string, key []byte, iv []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Encrypt the content
	encrypted := aesGCM.Seal(nil, iv, []byte(content), nil)

	// Return the encrypted content and the tag
	// The last 16 bytes are the tag for authentication
	tag := encrypted[len(encrypted)-16:]
	encryptedContent := encrypted[:len(encrypted)-16]

	// Convert to base64 for safe storage
	return base64.StdEncoding.EncodeToString(encryptedContent),
		base64.StdEncoding.EncodeToString(tag),
		nil
}

// EncryptKey encrupts the key for storage
//
// receives: key []byte
//
// returns: encrypted key, error
func EncryptKey(key []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(key), nil
}

// DecryptKey descriptografa a chave armazenada
func DecryptKey(hashedKey string) ([]byte, error) {
	// Por enquanto, vamos apenas decodificar o base64
	// TODO: Implementar descriptografia real da chave
	return base64.StdEncoding.DecodeString(hashedKey)
}

// DecryptContent descriptografa o conteúdo usando AES-GCM
func DecryptContent(hashedContent string, key []byte, iv []byte, tag string) (string, error) {
	// Decodifica o conteúdo do base64
	ciphertext, err := base64.StdEncoding.DecodeString(hashedContent)
	if err != nil {
		return "", fmt.Errorf("erro ao decodificar conteúdo: %v", err)
	}

	// Cria o cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("erro ao criar cipher: %v", err)
	}

	// Cria o GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("erro ao criar GCM: %v", err)
	}

	// Descriptografa
	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("erro ao descriptografar: %v", err)
	}

	return string(plaintext), nil
}

func GetUserFromSession(r *http.Request) *models.User {
	session, err := Store.Get(r, "session-ciphermemories")
	if err != nil {
		fmt.Printf("[ERROR] Failed to get session\n")
		return nil
	}

	userID, ok := session.Values["user_id"].(int64)
	if !ok {
		fmt.Printf("[ERROR] Invalid session data\n")
		return nil
	}

	// Get user from database
	var user models.User
	err = db.DB.QueryRow(`
		SELECT id, username, email, avatar_url, created_at, updated_at
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
		fmt.Printf("[ERROR] Failed to get user data from database\n")
		return nil
	}

	return &user
}
