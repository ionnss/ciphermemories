package handlers

import (
	"ciphermemories/db"
	"fmt"
	"html/template"
	"net/http"
)

var pageTemplates *template.Template

func init() {
	// Initialize templates
	pageTemplates = template.Must(template.ParseGlob("templates/*.html"))
	template.Must(pageTemplates.ParseGlob("templates/partials/*.html"))
}

// IndexPage serves the main page
func IndexPage(w http.ResponseWriter, r *http.Request) {
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/index.html")
		return
	}
	http.ServeFile(w, r, "templates/index.html")
}

// LoginPage serves the login page/partial
func LoginPage(w http.ResponseWriter, r *http.Request) {
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/login.html")
		return
	}
	http.ServeFile(w, r, "templates/login.html")
}

// RegisterPage serves the register page/partial
func RegisterPage(w http.ResponseWriter, r *http.Request) {
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/register.html")
		return
	}
	http.ServeFile(w, r, "templates/register.html")
}

// TermsPage serves the terms page/partial
func TermsPage(w http.ResponseWriter, r *http.Request) {
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/terms.html")
		return
	}
	http.ServeFile(w, r, "templates/terms.html")
}

// PrivacyPage serves the privacy page/partial
func PrivacyPage(w http.ResponseWriter, r *http.Request) {
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/privacy.html")
		return
	}
	http.ServeFile(w, r, "templates/privacy.html")
}

// DashboardPage serves the dashboard page/partial
func DashboardPage(w http.ResponseWriter, r *http.Request) {
	// Get user data from session
	session, _ := Store.Get(r, "session-ciphermemories")
	userID := session.Values["user_id"].(int)

	// Get user data from database
	var user struct {
		ID        int
		Username  string
		AvatarURL string
	}

	err := db.DB.QueryRow(`
		SELECT id, username, COALESCE(avatar_url, '/static/assets/default-avatar.png') as avatar_url
		FROM users 
		WHERE id = $1
	`, userID).Scan(&user.ID, &user.Username, &user.AvatarURL)

	if err != nil {
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return
	}

	// Execute template with user data
	data := map[string]interface{}{
		"ViewingUser": user,
		"CurrentPage": "dashboard",
	}

	err = pageTemplates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// RenderTemplate renders a partial template with the given data
func RenderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	fmt.Printf("RenderTemplate: rendering %s with data: %+v\n", templateName, data)

	tmpl, err := template.ParseFiles("templates/partials/" + templateName + ".html")
	if err != nil {
		fmt.Printf("RenderTemplate failed: error parsing template: %v\n", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		fmt.Printf("RenderTemplate failed: error executing template: %v\n", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
	fmt.Printf("RenderTemplate: completed successfully\n")
}
