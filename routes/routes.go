package routes

import (
	"net/http"

	"ciphermemories/handlers"

	"github.com/gorilla/mux"
)

func ConfigureRoutes(r *mux.Router) {
	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Pages
	r.HandleFunc("/", handlers.IndexPage).Methods("GET")
	r.HandleFunc("/login", handlers.LoginPage).Methods("GET")
	r.HandleFunc("/register", handlers.RegisterPage).Methods("GET")
	r.HandleFunc("/terms", handlers.TermsPage).Methods("GET")
	r.HandleFunc("/privacy", handlers.PrivacyPage).Methods("GET")

	// Actions
	r.HandleFunc("/register", handlers.RegisterUser).Methods("POST")
	r.HandleFunc("/verify", handlers.VerifyEmail).Methods("GET")
	r.HandleFunc("/login", handlers.LoginUser).Methods("POST")
	r.HandleFunc("/logout", handlers.LogoutUser).Methods("POST")
}
