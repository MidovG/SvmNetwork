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

func (d *Database) GetUserId(email string) int {
	var userId int
	err := d.db.QueryRow("select id from svm_network.users where email = ?", email).Scan(&userId)

	if err != nil {
		return 0
	} else {
		return userId
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

func (d *Database) DeleteUserById() {
	_, err := d.db.Exec("delete from svm_network.users where id = ?;")
	if err != nil {
		log.Println(err)
	}
}

func (d *Database) AddPersonalInfo(first_name, last_name, email string, userId int) error {
	_, err := d.db.Exec("insert into svm_network.user_profiles(user_id, first_name, last_name) values(?,?,?)", userId, first_name, last_name)

	if err != nil {
		return err
	}

	return nil
}

func (d *Database) CreateSession(userId int, token string) error {
	_, err := d.db.Exec("INSERT INTO user_sessions (user_id, session_token, expires_at, created_at, remember_session) VALUES (?, ?, ?, ?, ?)",
		userId, token, time.Now().Add(sessionDuration), time.Now(), true)
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) GetUserToken(userId int) (userToken string) {
	err := d.db.QueryRow("select session_token from svm_network.user_sessions where user_id = ?", userId).Scan(&userToken)

	if err != nil {
		log.Println("Ошибка получения токена: ", err)
	}

	return
}

func (d *Database) IsValidToken(userId int) bool {
	var expiriesTime string
	err := d.db.QueryRow("select expires_at	from svm_network.user_sessions where user_id = ?", userId).Scan(&expiriesTime)

	if err != nil {
		log.Println("Ошибка провверки валидности токена: ", err)
	}

	expDT, errOfParsing := time.Parse("2006-01-02 15:04:05", expiriesTime)

	if errOfParsing != nil {
		log.Println("Ошибка парсинга времени: ", errOfParsing)
	}

	if expDT == time.Now() {
		return false
	}

	return true
}
