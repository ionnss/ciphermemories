package handlers

import (
	"ciphermemories/db"
	"ciphermemories/models"
	"context"
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

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
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
	session.Save(r, w)

	// Limpa outros cookies relacionados
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, "cipher_") {
			c := &http.Cookie{
				Name:     cookie.Name,
				Value:    "",
				Path:     "/",
				Domain:   os.Getenv("COOKIE_DOMAIN"),
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, c)
		}
	}
}

// CreateSession cria uma nova sessão com os valores apropriados
func CreateSession(w http.ResponseWriter, r *http.Request, userID int64, username string) error {
	session, _ := Store.Get(r, "session-ciphermemories")

	// Limpa qualquer sessão existente
	session.Values = make(map[interface{}]interface{})

	// Define os valores da sessão
	session.Values["authenticated"] = true
	session.Values["user_id"] = userID
	session.Values["username"] = username
	session.Values["version"] = os.Getenv("APP_VERSION")
	session.Values["created_at"] = time.Now().Unix()
	session.Values["last_activity"] = time.Now().Unix()

	// Get the host from the request
	host := r.Host
	fmt.Printf("Request host: %s\n", host)

	// Set cookie domain based on environment
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
		cookieDomain = "" // Empty domain for localhost
	}

	// Ensure cookie settings are correct
	session.Options = &sessions.Options{
		Path:     "/",
		Domain:   cookieDomain,
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	fmt.Printf("Creating session with version: %s and domain: %s\n",
		os.Getenv("APP_VERSION"),
		cookieDomain)

	err := session.Save(r, w)
	if err != nil {
		fmt.Printf("Error saving session: %v\n", err)
		return err
	}

	fmt.Printf("Session saved successfully with domain: %s\n", cookieDomain)
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
		LogSessionIssue(r, fmt.Sprintf("Error getting session: %v", err))
		return false
	}

	// Add debug logging here
	sessionVersion, ok := session.Values["version"].(string)
	envVersion := os.Getenv("APP_VERSION")
	fmt.Printf("Session Version: %v (ok=%v), ENV Version: %s\n", sessionVersion, ok, envVersion)

	// Verifica a versão do app
	if !ok || sessionVersion != envVersion {
		LogSessionIssue(r, fmt.Sprintf("Invalid app version - Session: %v, ENV: %s", sessionVersion, envVersion))
		ClearSession(w, r)
		return false
	}

	// Verifica a idade da sessão
	if created, ok := session.Values["created_at"].(int64); ok {
		if time.Now().Unix()-created > 7*24*60*60 { // 7 dias
			LogSessionIssue(r, "Session expired (age)")
			ClearSession(w, r)
			return false
		}
	}

	// Verifica última atividade
	if lastActivity, ok := session.Values["last_activity"].(int64); ok {
		if time.Now().Unix()-lastActivity > 3600 { // 1 hora
			LogSessionIssue(r, "Session expired (inactivity)")
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

// UploadToCloudinary uploads a file to Cloudinary
//
// receives: file io.Reader
//
// returns: URL of the uploaded file, error
func UploadToCloudinary(file io.Reader) (string, error) {
	fmt.Printf("UploadToCloudinary: starting upload\n")

	// Pegar URL do Cloudinary do .env
	cloudinaryURL := os.Getenv("CLOUDINARY_URL")
	if cloudinaryURL == "" {
		return "", fmt.Errorf("CLOUDINARY_URL environment variable is not set")
	}
	fmt.Printf("UploadToCloudinary: got Cloudinary URL\n")

	// Criar cliente Cloudinary
	cld, err := cloudinary.NewFromURL(cloudinaryURL)
	if err != nil {
		fmt.Printf("UploadToCloudinary failed: error creating client: %v\n", err)
		return "", err
	}
	fmt.Printf("UploadToCloudinary: client created successfully\n")

	// Fazer upload
	fmt.Printf("UploadToCloudinary: attempting upload to profiles folder\n")
	uploadResult, err := cld.Upload.Upload(
		context.Background(),
		file,
		uploader.UploadParams{
			Folder: "profiles",
		},
	)

	if err != nil {
		fmt.Printf("UploadToCloudinary failed: error uploading: %v\n", err)
		return "", err
	}
	fmt.Printf("UploadToCloudinary: upload successful - URL: %s\n", uploadResult.SecureURL)

	return uploadResult.SecureURL, nil
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
		fmt.Printf("GetUserFromSession failed: error getting session: %v\n", err)
		fmt.Printf("Request cookies: %+v\n", r.Cookies())
		return nil
	}

	// Debug: print all session values
	fmt.Printf("Session values: %+v\n", session.Values)
	fmt.Printf("Session options: %+v\n", session.Options)

	userID, ok := session.Values["user_id"].(int64)
	if !ok {
		fmt.Printf("GetUserFromSession failed: could not convert user_id to int64. Value: %v, Type: %T\n",
			session.Values["user_id"], session.Values["user_id"])
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
		fmt.Printf("GetUserFromSession failed: error getting user from database: %v\n", err)
		return nil
	}

	return &user
}
