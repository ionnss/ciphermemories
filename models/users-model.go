package models

import "time"

type User struct {
	ID              int64     `json:"id" db:"id"`
	Username        string    `json:"username" db:"username"`
	Email           string    `json:"email" db:"email"`
	Password        string    `json:"password" db:"password"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
	Bio             string    `json:"bio" db:"bio"`
	BirthDate       time.Time `json:"birth_date" db:"birth_date"`
	BirthLocation   string    `json:"birth_location" db:"birth_location"`
	CurrentLocation string    `json:"current_location" db:"current_location"`
	AvatarURL       string    `json:"avatar_url" db:"avatar_url"`
}
