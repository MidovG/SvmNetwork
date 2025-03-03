package repo

import (
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (d *Database) AddNewUser(username, email, password string) error {
	hashedPassword, errOfHashed := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if errOfHashed != nil {
		log.Println("Ошибка при хэшировании:", errOfHashed)
		return errOfHashed
	}

	_, err := d.db.Exec("insert into svm_network.users(name, email, password_hash, created_at, updated_at, is_active) values(?,?,?,?,?,?)", username, email, hashedPassword, time.Now(), time.Now(), true)

	if err != nil {
		log.Println("Ошибка добавления данных пользователя: ", err)
		return err
	}

	return nil
}

func (d *Database) CheckPassword(email, password string) bool {
	var password_hash string
	err := d.db.QueryRow("select password_hash from svm_network.users where email = ?", email).Scan(&password_hash)

	if err != nil {
		log.Println("Ошибка: ", err)
	}

	errOfCheckHash := bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))

	if errOfCheckHash != nil {
		log.Println("Пароли не совпадают: ", errOfCheckHash)
		return false
	} else {
		log.Println("Пароли совпадают")
		return true
	}
}

func (d *Database) GetUserId(email string) (int, bool) {
	var userId int
	err := d.db.QueryRow("select id from svm_network.users where email = ?", email).Scan(&userId)

	if err != nil {
		return 0, false
	} else {
		return userId, true
	}
}

func (d *Database) CheckExist(email string) bool {
	var userId int
	err := d.db.QueryRow("select id from svm_network.users where email = ?", email).Scan(&userId)

	if err != nil {
		return false
	} else {
		return true
	}
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
	_, err := d.db.Exec("delete from svm_network.users where id = ?;")
	if err != nil {
		log.Println(err)
	}
}
