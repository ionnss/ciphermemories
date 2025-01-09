package handlers

import (
	"ciphermemories/db"
	"ciphermemories/models"
	"encoding/base64"
	"net/http"
	"strconv"
)

// CreateMemory creates a new memory
//
// receives:
// - w http.ResponseWriter: the response writer
// - r *http.Request: the request
//
// returns:
// - void
func CreateMemory(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	user := GetUserFromSession(r)
	if user == nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "User not found"}`)
		http.Error(w, "User not found", http.StatusUnauthorized)
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

	// Validate required fields and sizes
	if title == "" || content == "" {
		w.Header().Set("HX-Trigger", `{"showMessage": "Title and content are required"}`)
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	// Validate title length
	if len(title) > 255 {
		w.Header().Set("HX-Trigger", `{"showMessage": "Title must be less than 255 characters"}`)
		http.Error(w, "Title too long", http.StatusBadRequest)
		return
	}

	// Validate content length (exemplo: máximo 10000 caracteres)
	if len(content) > 10000 {
		w.Header().Set("HX-Trigger", `{"showMessage": "Content is too long"}`)
		http.Error(w, "Content too long", http.StatusBadRequest)
		return
	}

	// Validate status and pricing rules
	switch status {
	case "public":
		isPaid = "false"
		price = "0"
	case "private":
		if isPaid == "true" {
			priceInt, err := strconv.Atoi(price)
			if err != nil || priceInt < 10 {
				w.Header().Set("HX-Trigger", `{"showMessage": "Price must be at least 10 USD"}`)
				http.Error(w, "Invalid price", http.StatusBadRequest)
				return
			}
		} else {
			// Se não é paga, preço deve ser 0
			price = "0"
		}
	default:
		w.Header().Set("HX-Trigger", `{"showMessage": "Invalid status"}`)
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	// Convert string values to appropriate types
	isPaidBool, _ := strconv.ParseBool(isPaid)
	priceInt, _ := strconv.Atoi(price)

	// Generate random key for this specific memory
	key, err := GenerateRandomKey()
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error generating encryption key"}`)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Gerar IV (vetor de inicialização) - necessário para a criptografia
	iv, err := GenerateIV()
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Erro ao gerar vetor de inicialização"}`)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Encrypt the memory content using the key and the IV
	hashedContent, encryptionTag, err := EncryptContent(content, key, iv)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Erro ao criptografar conteúdo"}`)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Encrypt the key for storage
	hashedKey, err := EncryptKey(key)
	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error encrypting key"}`)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert IV to base64 for storage
	encryptionIV := base64.StdEncoding.EncodeToString(iv)

	// Create memory
	memory := models.Memory{
		CreatorID:     creatorID,
		Title:         title,
		HashedContent: hashedContent,
		HashedKey:     hashedKey,
		EncryptionIV:  encryptionIV,
		EncryptionTag: encryptionTag,
		Status:        status,
		IsPaid:        isPaidBool,
		Price:         priceInt,
	}

	// Insert memory in database and return the ID
	query := `
        INSERT INTO memories (
            creator_id, title, hashed_content, hashed_key, 
            encryption_iv, encryption_tag, status, is_paid, price
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
    `

	var memoryID int64
	err = db.DB.QueryRow(query,
		memory.CreatorID,
		memory.Title,
		memory.HashedContent,
		memory.HashedKey,
		memory.EncryptionIV,
		memory.EncryptionTag,
		memory.Status,
		memory.IsPaid,
		memory.Price,
	).Scan(&memoryID)

	if err != nil {
		w.Header().Set("HX-Trigger", `{"showMessage": "Error saving memory"}`)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Sucesso com múltiplos triggers
	w.Header().Set("HX-Trigger", `{
        "showMessage": "Memory Ciphered!",
        "clearForm": true,
        "refreshFeed": true
    }`)
	w.WriteHeader(http.StatusCreated)
}

// IndexMemoriesCount returns the number of memories ever created
//
// receives:
// - w http.ResponseWriter: the response writer
// - r *http.Request: the request
//
// returns:
// - void
func IndexMemoriesCount(w http.ResponseWriter, r *http.Request) {

}

// GetMemoriesFeed returns a list of memories for the feed
//
// receives:
// - w http.ResponseWriter: the response writer
// - r *http.Request: the request
//
// returns:
// - void
func GetMemoriesFeed(w http.ResponseWriter, r *http.Request) {

}
