package routes

import (
	"ciphermemories/handlers"
	"net/http"

	"github.com/gorilla/mux"
)

func ConfigureRoutes(r *mux.Router) {
	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Rotas públicas com SecurityMiddleware
	public := r.PathPrefix("").Subrouter()
	public.Use(handlers.SecurityMiddleware)

	// Pages
	public.HandleFunc("/", handlers.IndexPage).Methods("GET")
	public.HandleFunc("/login", handlers.LoginPage).Methods("GET")
	public.HandleFunc("/register", handlers.RegisterPage).Methods("GET")
	public.HandleFunc("/terms", handlers.TermsPage).Methods("GET")
	public.HandleFunc("/privacy", handlers.PrivacyPage).Methods("GET")

	// Auth actions
	public.HandleFunc("/register", handlers.RegisterUser).Methods("POST")
	public.HandleFunc("/verify", handlers.VerifyEmail).Methods("GET")
	public.HandleFunc("/login", handlers.LoginUser).Methods("POST")

	// Rotas protegidas com SecurityMiddleware E AuthMiddleware
	protected := r.PathPrefix("").Subrouter()
	protected.Use(handlers.SecurityMiddleware)
	protected.Use(handlers.AuthMiddleware)

	// Protected actions
	protected.HandleFunc("/dashboard", handlers.DashboardPage).Methods("GET")
	protected.HandleFunc("/profile", handlers.ProfilePage).Methods("GET")
	protected.HandleFunc("/logout", handlers.LogoutUser).Methods("POST")
}
