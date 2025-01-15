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

	if !ValidateSession(w, r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Get user from session using our updated GetUserFromSession function
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return
	}

	// Debug logging
	//fmt.Printf("DashboardPage: User data: %+v\n", user)

	// Execute template with user data
	data := map[string]interface{}{
		"ViewingUser": user,
		"CurrentPage": "dashboard",
	}

	err := pageTemplates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		fmt.Printf("DashboardPage: Template error: %v\n", err)
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

// SettingsPage serves the settings page/partial
func SettingsPage(w http.ResponseWriter, r *http.Request) {
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/settings.html")
		return
	}
	http.ServeFile(w, r, "templates/settings.html")
}

// MemoriesManagerPage serves the memories manager page/partial
func MemoriesManagerPage(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Check if this is a setup request
	if r.Method == "POST" {
		SetupMemoriesManager(w, r)
		return
	}

	// Check if user has memories manager
	var hasManager bool
	err := db.DB.QueryRow(`
		SELECT has_memories_manager 
		FROM users 
		WHERE id = $1
	`, user.ID).Scan(&hasManager)

	if err != nil {
		http.Error(w, "Error checking memories manager status", http.StatusInternalServerError)
		return
	}

	// Update user struct with memories manager status
	user.HasMemoriesManager = hasManager

	// Prepare data for the template
	data := map[string]interface{}{
		"ViewingUser": user,
		"CurrentPage": "memories-manager",
	}

	// Render the dashboard template
	err = pageTemplates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		fmt.Printf("Error rendering dashboard: %v\n", err)
		http.Error(w, "Error rendering dashboard", http.StatusInternalServerError)
		return
	}
}

// MemoriesManagerSetupPage serves the memories manager setup page/partial
func MemoriesManagerSetupPage(w http.ResponseWriter, r *http.Request) {
	if !ValidateSession(w, r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "templates/memories_manager_setup.html")
}
