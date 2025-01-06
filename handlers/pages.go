package handlers

import (
	"net/http"
)

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
	// Check if it's an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		http.ServeFile(w, r, "templates/dashboard.html")
		return
	}
	http.ServeFile(w, r, "templates/dashboard.html")
}
