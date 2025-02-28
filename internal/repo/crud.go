package repo

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (d *Database) CheckUserForLogin(email, password string) (ok bool, err error) {
	var storedHash string
	err = d.db.QueryRow("SELECT password_hash FROM users WHERE email = ?", email).Scan(&storedHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (d *Database) GetUserId(email string) (int, error) {
	var userId int

	err := d.db.QueryRow("select id from users where email = ?", email).Scan(&userId)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("пользователь с email %s не найден", email)
		}
		return 0, fmt.Errorf("ошибка при получении ID пользователя: %v", err)
	}

	return userId, nil
}

func (d *Database) CheckUserForExist(email string) (ok bool, err error) {
	var storedHash int
	err = d.db.QueryRow("SELECT id from users where email = ?", email).Scan(&storedHash)

	if err != nil {
		return true, err
	}

	return false, err
}

func (d *Database) AddNewUser(name, email, password string) (ok bool, err error) {
	// exists, err := d.CheckUserForExist(email)
	// if err != nil {
	// 	return false, err
	// }
	// if exists {
	// 	return false, errors.New("пользователь с таким email уже существует")
	// }

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	_, err = d.db.Exec("INSERT INTO users (name, email, password_hash, created_at, updated_at, is_active) VALUES (?, ?, ?, ?, ?, ?)", name, email, hashedPassword, time.Now(), time.Now(), true)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (d *Database) CreateSession(userID int, token string) error {
	_, err := d.db.Exec("INSERT INTO user_sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?)",
		userID, token, time.Now().Add(sessionDuration), time.Now())
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) DeleteUserById() {
	_, err := d.db.Exec("delete from base_crud_bd.users where id = ?;")
	if err != nil {
		log.Println(err)
	}
}
