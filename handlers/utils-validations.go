package handlers

import (
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

	// Configuração segura para o cookie de sessão
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 dias
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Debug da configuração
	fmt.Printf("Cookie store initialized with options: %+v\n", Store.Options)
}

// AuthHandler verifies if the user is authenticated
//
// receives: w http.ResponseWriter, r *http.Request
//
// returns: error
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "session-ciphermemories")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verifica se o usuário está autenticado
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
		session, err := Store.Get(r, "session-ciphermemories")
		if err != nil {
			if r.Header.Get("HX-Request") == "true" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		// Verifica se o usuário está autenticado
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			if r.Header.Get("HX-Request") == "true" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		// Verifica se a sessão expirou
		if lastActivity, ok := session.Values["last_activity"].(int64); ok {
			if time.Now().Unix()-lastActivity > 3600 { // 1 hora
				session.Options.MaxAge = -1
				session.Save(r, w)
				if r.Header.Get("HX-Request") == "true" {
					http.Error(w, "Session expired", http.StatusUnauthorized)
				} else {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
				}
				return
			}
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
