package handlers

import (
	"bytes"
	"ciphermemories/db"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"image"
	"image/jpeg"
	"image/png"

	"github.com/disintegration/imaging"
	"github.com/google/uuid"
)

// RenderSettings renders the settings page
func RenderSettings(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"ViewingUser": user,
		"CurrentPage": "settings",
	}

	err := pageTemplates.ExecuteTemplate(w, "settings.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// HandleAvatarUpload handles the avatar upload
func HandleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromSession(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse the multipart form
	err := r.ParseMultipartForm(10 << 20) // 10 MB max
	if err != nil {
		fmt.Printf("Failed to parse form: %v\n", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		fmt.Printf("Failed to get form file: %v\n", err)
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file type
	if !isValidImageType(header.Filename) {
		fmt.Printf("Invalid file type: %s\n", header.Filename)
		http.Error(w, "Invalid file type. Only images are allowed", http.StatusBadRequest)
		return
	}

	// Create unique filename
	filename := fmt.Sprintf("%s%s", uuid.New().String(), filepath.Ext(header.Filename))
	fmt.Printf("Generated filename: %s\n", filename)

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Failed to get working directory: %v\n", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Ensure uploads directory exists with full path
	uploadsDir := filepath.Join(cwd, "static", "uploads", "avatars")
	fmt.Printf("Creating directory: %s\n", uploadsDir)
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Read the image for processing
	imgData, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		http.Error(w, "Failed to process image", http.StatusInternalServerError)
		return
	}

	// Decode the image
	img, imgType, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		fmt.Printf("Failed to decode image: %v\n", err)
		http.Error(w, "Failed to process image", http.StatusInternalServerError)
		return
	}

	// Resize the image to 200x200
	resized := imaging.Fit(img, 200, 200, imaging.Lanczos)

	// Create the output file
	fullPath := filepath.Join(uploadsDir, filename)
	fmt.Printf("Saving file to: %s\n", fullPath)

	out, err := os.Create(fullPath)
	if err != nil {
		fmt.Printf("Failed to create file: %v\n", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	// Encode and save the resized image
	switch imgType {
	case "jpeg", "jpg":
		err = jpeg.Encode(out, resized, &jpeg.Options{Quality: 85})
	case "png":
		err = png.Encode(out, resized)
	default:
		err = jpeg.Encode(out, resized, &jpeg.Options{Quality: 85})
	}

	if err != nil {
		fmt.Printf("Failed to encode and save image: %v\n", err)
		http.Error(w, "Failed to save image", http.StatusInternalServerError)
		return
	}

	// Delete old avatar if it exists and isn't the default
	oldAvatarURL := user.AvatarURL
	if oldAvatarURL != "" && oldAvatarURL != "/static/assets/default-avatar.png" {
		oldAvatarPath := filepath.Join(cwd, strings.TrimPrefix(oldAvatarURL, "/"))
		if err := os.Remove(oldAvatarPath); err != nil {
			fmt.Printf("Failed to delete old avatar: %v\n", err)
		}
	}

	// Update user's avatar URL in database
	avatarURL := fmt.Sprintf("/static/uploads/avatars/%s", filename)
	err = updateUserAvatar(user.ID, avatarURL)
	if err != nil {
		http.Error(w, "Failed to update avatar", http.StatusInternalServerError)
		return
	}

	// Return success message and new avatar URL
	w.Header().Set("Content-Type", "text/html")
	successHTML := fmt.Sprintf(`
		<div class="success">Avatar updated successfully!</div>
		<script>
			// Update all instances of the user's avatar
			document.querySelectorAll('img[src="%s"]').forEach(img => {
				img.src = "%s";
			});
			// Also update any instances with the default avatar
			document.querySelectorAll('img[src="/static/assets/default-avatar.png"]').forEach(img => {
				img.src = "%s";
			});
		</script>
	`, oldAvatarURL, avatarURL, avatarURL)
	w.Write([]byte(successHTML))
}

// isValidImageType checks if the file is an allowed image type
func isValidImageType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	validTypes := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
	}
	return validTypes[ext]
}

// updateUserAvatar updates the user's avatar URL in the database
func updateUserAvatar(userID int64, avatarURL string) error {
	_, err := db.DB.Exec("UPDATE users SET avatar_url = $1 WHERE id = $2", avatarURL, userID)
	return err
}
