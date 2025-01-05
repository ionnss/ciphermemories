package routes

import (
	"net/http"

	"github.com/gorilla/mux"
)

func ConfigureRoutes(r *mux.Router) {
	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Serve index page
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	})

	// Serve login page
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/login.html")
	})

	// Serve register page
	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/register.html")
	})
}
