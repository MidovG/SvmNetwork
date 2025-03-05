package userModel

import (
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

const sessionDuration = time.Hour

func CreateJWTToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().UTC().Add(sessionDuration).Unix(),
	})

	tokenString, err := token.SignedString([]byte("usersecretkey"))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func IsValidToken(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("token")

	if err != nil {
		log.Println("Ошибка получения куков")
		return false
	}

	tokenString := cookie.Value

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("usersecretkey"), nil
	})

	if err != nil || !token.Valid {
		log.Println("Недействительный токен")
		return false
	}

	claims := token.Claims.(jwt.MapClaims)
	if float64(time.Now().UTC().Unix()) > claims["exp"].(float64) {
		log.Println("Токен истек")
		return false
	}

	log.Println("Токен действителен")

	return true
}

func SetUserCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   1 * 60 * 60,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

func ResetUserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().UTC().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
