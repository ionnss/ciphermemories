package models

import "time"

type User struct {
	ID              int64
	Username        string
	Email           string
	Password        string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Bio             string
	BirthDate       time.Time
	BirthLocation   string
	CurrentLocation string
	AvatarURL       string
}
