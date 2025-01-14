package handlers

import (
	"ciphermemories/db"
	"ciphermemories/models"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// IndexMemoriesCount retorna o total de memórias criptografadas
func IndexMemoriesCount(w http.ResponseWriter, r *http.Request) {
	// Obtém o total de memórias do banco de dados
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM memories").Scan(&count)
	if err != nil {
		http.Error(w, "Erro ao contar memórias", http.StatusInternalServerError)
		return
	}

	// Retorna apenas o número
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%d", count)
}

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

// GetMemories retorna uma lista paginada de memórias
func GetMemories(w http.ResponseWriter, r *http.Request) {
	// Obtém o usuário da sessão
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "Usuário não encontrado", http.StatusUnauthorized)
		return
	}

	// Obtém o offset da query string (para paginação)
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		offset, _ = strconv.Atoi(offsetStr)
	}

	// Query para buscar as memórias mais recentes
	query := `
		SELECT m.id, m.title, m.hashed_content, m.hashed_key, m.encryption_iv, m.encryption_tag,
			   m.status, m.is_paid, m.price, m.created_at,
			   u.id as user_id, u.username, 
			   COALESCE(u.avatar_url, '/static/assets/default-avatar.png') as avatar_url
		FROM memories m
		JOIN users u ON m.creator_id = u.id
		ORDER BY m.created_at DESC
		LIMIT 50 OFFSET $1
	`

	// Executa a query
	rows, err := db.DB.Query(query, offset)
	if err != nil {
		http.Error(w, "Erro ao buscar memórias", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Template para formatar o tempo
	timeTemplate := "2 Jan 2006"

	// Processa cada memória
	var memories []struct {
		ID        int64     `json:"id"`
		Title     string    `json:"title"`
		Content   string    `json:"content"`
		Status    string    `json:"status"`
		IsPaid    bool      `json:"is_paid"`
		Price     int       `json:"price"`
		CreatedAt time.Time `json:"created_at"`
		User      struct {
			ID        int64  `json:"id"`
			Username  string `json:"username"`
			AvatarURL string `json:"avatar_url"`
		} `json:"user"`
		FormattedTime string `json:"formatted_time"`
	}

	for rows.Next() {
		var m struct {
			ID            int64
			Title         string
			HashedContent string
			HashedKey     string
			EncryptionIV  string
			EncryptionTag string
			Status        string
			IsPaid        bool
			Price         int
			CreatedAt     time.Time
			UserID        int64
			Username      string
			AvatarURL     string
		}

		err := rows.Scan(
			&m.ID, &m.Title, &m.HashedContent, &m.HashedKey, &m.EncryptionIV, &m.EncryptionTag,
			&m.Status, &m.IsPaid, &m.Price, &m.CreatedAt,
			&m.UserID, &m.Username, &m.AvatarURL,
		)
		if err != nil {
			continue
		}

		memory := struct {
			ID        int64     `json:"id"`
			Title     string    `json:"title"`
			Content   string    `json:"content"`
			Status    string    `json:"status"`
			IsPaid    bool      `json:"is_paid"`
			Price     int       `json:"price"`
			CreatedAt time.Time `json:"created_at"`
			User      struct {
				ID        int64  `json:"id"`
				Username  string `json:"username"`
				AvatarURL string `json:"avatar_url"`
			} `json:"user"`
			FormattedTime string `json:"formatted_time"`
		}{
			ID:        m.ID,
			Title:     m.Title,
			Status:    m.Status,
			IsPaid:    m.IsPaid,
			Price:     m.Price,
			CreatedAt: m.CreatedAt,
		}

		// Adiciona o conteúdo apenas se for pública
		if m.Status == "public" {
			// Descriptografa o conteúdo
			iv, err := base64.StdEncoding.DecodeString(m.EncryptionIV)
			if err != nil {
				fmt.Printf("Erro ao decodificar IV: %v\n", err)
				continue
			}

			key, err := DecryptKey(m.HashedKey)
			if err != nil {
				fmt.Printf("Erro ao descriptografar chave: %v\n", err)
				continue
			}

			tag, err := base64.StdEncoding.DecodeString(m.EncryptionTag)
			if err != nil {
				fmt.Printf("Erro ao decodificar tag: %v\n", err)
				continue
			}

			// Concatena o conteúdo com a tag para descriptografia
			encryptedData, err := base64.StdEncoding.DecodeString(m.HashedContent)
			if err != nil {
				fmt.Printf("Erro ao decodificar conteúdo: %v\n", err)
				continue
			}

			fullData := append(encryptedData, tag...)
			content, err := DecryptContent(base64.StdEncoding.EncodeToString(fullData), key, iv, m.EncryptionTag)
			if err != nil {
				fmt.Printf("Erro ao descriptografar conteúdo: %v\n", err)
				continue
			}

			memory.Content = content
		}

		// Adiciona informações do usuário
		memory.User.ID = m.UserID
		memory.User.Username = m.Username
		memory.User.AvatarURL = m.AvatarURL

		// Formata o tempo
		memory.FormattedTime = m.CreatedAt.Format(timeTemplate)

		memories = append(memories, memory)
	}

	// Renderiza o template parcial com as memórias
	err = pageTemplates.ExecuteTemplate(w, "memories", memories)
	if err != nil {
		http.Error(w, "Erro ao renderizar memórias", http.StatusInternalServerError)
		return
	}
}

// CheckNewMemories verifica se existem novas memórias desde um determinado timestamp
func CheckNewMemories(w http.ResponseWriter, r *http.Request) {
	// Obtém o timestamp da última memória
	since := r.URL.Query().Get("since")
	if since == "" {
		http.Error(w, "Parâmetro 'since' é obrigatório", http.StatusBadRequest)
		return
	}

	// Converte para int64
	timestamp, err := strconv.ParseInt(since, 10, 64)
	if err != nil {
		http.Error(w, "Timestamp inválido", http.StatusBadRequest)
		return
	}

	// Converte para time.Time
	sinceTime := time.Unix(timestamp, 0)

	// Conta quantas memórias novas existem
	var count int
	err = db.DB.QueryRow(`
		SELECT COUNT(*) 
		FROM memories 
		WHERE created_at > $1
	`, sinceTime).Scan(&count)

	if err != nil {
		http.Error(w, "Erro ao contar novas memórias", http.StatusInternalServerError)
		return
	}

	// Retorna o resultado como JSON
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"count": %d}`, count)
}

func PrivateMemoriesManager(w http.ResponseWriter, r *http.Request) {
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

	// If user doesn't have memories manager, show setup page
	if !hasManager {
		err = pageTemplates.ExecuteTemplate(w, "memories_manager_setup.html", nil)
		if err != nil {
			http.Error(w, "Error rendering setup page", http.StatusInternalServerError)
		}
		return
	}

	// If user has memories manager, show the manager page
	err = pageTemplates.ExecuteTemplate(w, "memories_manager.html", nil)
	if err != nil {
		http.Error(w, "Error rendering manager page", http.StatusInternalServerError)
	}
}

// Helper function to handle the setup process
func SetupMemoriesManager(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Get password from user input
	password := r.FormValue("password")

	// Validate password
	if !ValidatePassword(password) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<div class="alert alert-danger">Invalid password format</div>`)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div class="alert alert-danger">Error processing password</div>`)
		return
	}

	// Update user with hashed password and enable memories manager
	_, err = db.DB.Exec(`
		UPDATE users 
		SET memories_password_hash = $1, has_memories_manager = true 
		WHERE id = $2
	`, hashedPassword, user.ID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div class="alert alert-danger">Error saving password</div>`)
		return
	}

	// Send confirmation email
	emailData := &EmailDataMemoriesManager{
		Title:        "Memory Manager Activated",
		Message:      fmt.Sprintf("Your password for the Memory Manager has been set, %s. You can now manage your private memories.", user.Username),
		AttentionBox: "Keep this password safe! It cannot be recovered if lost.",
		Password:     password,
	}

	err = MemoryManagerSendEmail(user.Email, "Memory Manager Activated", emailData)
	if err != nil {
		fmt.Printf("[ERROR] Error sending email: %v\n", err)
		w.WriteHeader(http.StatusOK) // Still return OK since the setup was successful
		fmt.Fprintf(w, `<div class="alert alert-warning">Memory Manager activated successfully, but there was an error sending the confirmation email. Please keep your password safe!</div>`)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<div class="alert alert-success">Memory Manager activated successfully! Redirecting...</div>`)
}

func ValidateMemoriesManagerPassword(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Get password from request
	password := r.FormValue("password")
	if password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<div class="alert alert-danger">Password is required</div>`)
		return
	}

	// Get stored password hash
	var storedHash string
	err := db.DB.QueryRow(`
		SELECT memories_password_hash 
		FROM users 
		WHERE id = $1
	`, user.ID).Scan(&storedHash)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div class="alert alert-danger">Error validating password</div>`)
		return
	}

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `<div class="alert alert-danger">Invalid password</div>`)
		return
	}

	// Create a temporary session token for memories access
	session, _ := Store.Get(r, "session-ciphermemories")
	session.Values["memories_access"] = true
	session.Values["memories_access_time"] = time.Now().Unix()

	err = session.Save(r, w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div class="alert alert-danger">Error creating session</div>`)
		return
	}

	// Return success
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<div class="alert alert-success">Access granted</div>`)
}

func GetPrivateMemories(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Verify memories access
	session, _ := Store.Get(r, "session-ciphermemories")
	memoryAccess, ok := session.Values["memories_access"].(bool)
	if !ok || !memoryAccess {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	// Check if access hasn't expired (30 minutes)
	accessTime, ok := session.Values["memories_access_time"].(int64)
	if !ok || time.Now().Unix()-accessTime > 1800 { // 30 minutes
		delete(session.Values, "memories_access")
		delete(session.Values, "memories_access_time")
		session.Save(r, w)
		http.Error(w, "Access expired", http.StatusUnauthorized)
		return
	}

	// Get user's private memories
	query := `
		SELECT m.id, m.title, m.hashed_content, m.hashed_key, m.encryption_iv, 
			   m.encryption_tag, m.created_at
		FROM memories m
		WHERE m.creator_id = $1 AND m.status = 'private'
		ORDER BY m.created_at DESC
	`

	rows, err := db.DB.Query(query, user.ID)
	if err != nil {
		http.Error(w, "Error fetching memories", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var memories []struct {
		ID        int64     `json:"id"`
		Title     string    `json:"title"`
		Content   string    `json:"content"`
		CreatedAt time.Time `json:"created_at"`
	}

	for rows.Next() {
		var m struct {
			ID            int64
			Title         string
			HashedContent string
			HashedKey     string
			EncryptionIV  string
			EncryptionTag string
			CreatedAt     time.Time
		}

		err := rows.Scan(
			&m.ID, &m.Title, &m.HashedContent, &m.HashedKey,
			&m.EncryptionIV, &m.EncryptionTag, &m.CreatedAt,
		)
		if err != nil {
			continue
		}

		// Decrypt memory content
		iv, _ := base64.StdEncoding.DecodeString(m.EncryptionIV)
		key, _ := DecryptKey(m.HashedKey)
		tag, _ := base64.StdEncoding.DecodeString(m.EncryptionTag)
		encryptedData, _ := base64.StdEncoding.DecodeString(m.HashedContent)

		fullData := append(encryptedData, tag...)
		content, err := DecryptContent(
			base64.StdEncoding.EncodeToString(fullData),
			key,
			iv,
			m.EncryptionTag,
		)
		if err != nil {
			continue
		}

		memories = append(memories, struct {
			ID        int64     `json:"id"`
			Title     string    `json:"title"`
			Content   string    `json:"content"`
			CreatedAt time.Time `json:"created_at"`
		}{
			ID:        m.ID,
			Title:     m.Title,
			Content:   content,
			CreatedAt: m.CreatedAt,
		})
	}

	// Render memories template
	err = pageTemplates.ExecuteTemplate(w, "private_memories", memories)
	if err != nil {
		http.Error(w, "Error rendering memories", http.StatusInternalServerError)
		return
	}
}
