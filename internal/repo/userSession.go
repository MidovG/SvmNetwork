package repo

import (
	"time"

	"github.com/golang-jwt/jwt"
)

const sessionDuration = time.Hour * 12

func CreateJWTToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(sessionDuration).Unix(),
	})

	tokenString, err := token.SignedString([]byte("usersecretkey"))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
