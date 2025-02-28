package userModel

import (
	"time"
)

// User - модель пользователя
type User struct {
	ID        int       `db:"id"`
	Username  string    `db:"username"`
	Email     string    `db:"email"`
	Password  string    `db:"password_hash"`
	CreatedAt time.Time `db:"created_at"`
}

// Session - модель сессии
type Session struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	SessionToken string    `db:"session_token"`
	ExpiresAt    time.Time `db:"expires_at"`
	CreatedAt    time.Time `db:"created_at"`
}
