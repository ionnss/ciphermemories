package handlers

import (
	"log"
	"net/http"
)

func CreateMemory(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	user := GetUserFromSession(r)
	if user == nil {
		log.Println("User not found")
		return
	}

	// Memory builder
	//
	// Get user's id
	creatorID := user.ID

	// Get data from Create Memory Form in dashboard
	title := r.FormValue("title")
	content := r.FormValue("content")
	status := r.FormValue("status")
	isPaid := r.FormValue("is_paid")
	price := r.FormValue("price")
}
