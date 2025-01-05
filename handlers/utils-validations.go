package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

// Store é a sessão do usuário
var Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

func init() {
	// Configuração segura para o cookie de sessão
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 dias
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// AuthHandler verifica se o usuário está autenticado
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "session-name")
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

// AuthMiddleware protege rotas que precisam de autenticação
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := Store.Get(r, "session-name")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Verifica se o usuário está autenticado
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Verifica se a sessão expirou
		if lastActivity, ok := session.Values["last_activity"].(int64); ok {
			if time.Now().Unix()-lastActivity > 3600 { // 1 hora
				session.Options.MaxAge = -1
				session.Save(r, w)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}

		// Atualiza o último acesso
		session.Values["last_activity"] = time.Now().Unix()
		session.Save(r, w)

		next.ServeHTTP(w, r)
	})
}

// GenerateVerificationToken gera um token único para verificação de email
//
// returns: token, error
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ValidateEmail verifica se o email está em um formato válido
//
// receives: email
//
// returns: true if email is valid, false otherwise
func validateEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateUsername verifica se o username está em um formato válido
//
// receives: username
//
// returns: true if username is valid, false otherwise
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

// SanitizeInput remove caracteres perigosos de uma string
func SanitizeInput(input string) string {
	// Remove espaços extras
	input = strings.TrimSpace(input)

	// Remove caracteres de controle
	input = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(input, "")

	return input
}
