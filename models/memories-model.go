package models

import "time"

// Memory is a struct that represents a memory
type Memory struct {
	ID                 int64     `json:"id" db:"id"`
	CreatorID          int64     `json:"creator_id" db:"creator_id"`
	Title              string    `json:"title" db:"title"`
	HashedContent      string    `json:"hashed_content" db:"hashed_content"`
	HashedKey          string    `json:"hashed_key" db:"hashed_key"`
	EncryptionIV       string    `json:"encryption_iv" db:"encryption_iv"`
	EncryptionTag      string    `json:"encryption_tag" db:"encryption_tag"`
	Status             string    `json:"status" db:"status"`
	IsPaid             bool      `json:"is_paid" db:"is_paid"`
	Price              int       `json:"price" db:"price"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	HasMemoriesManager bool      `json:"has_memories_manager" db:"has_memories_manager"`
}

// MemoriesAccess is a struct that represents a memory access
type MemoriesAccess struct {
	ID            int64     `json:"id" db:"id"`
	MemoryID      int64     `json:"memory_id" db:"memory_id"`
	BuyerID       int64     `json:"buyer_id" db:"buyer_id"`
	PurchasedAt   time.Time `json:"purchased_at" db:"purchased_at"`
	TransactionID string    `json:"transaction_id" db:"transaction_id"`
}
