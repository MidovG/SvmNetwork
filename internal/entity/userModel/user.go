package userModel

import (
	"time"
)

// User - модель пользователя
type User struct {
	ID        int
	Username  string
	Email     string
	Password  string
	CreatedAt time.Time
}

// UserProfile - модель данных профиля пользователя
type UserProfile struct {
	User_Id    int
	First_Name string
	Last_Name  string
}
