package repo

import (
	"database/sql"
	"errors"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func (d *Database) CheckUserForLogin(email, password string) (ok bool, err error) {
	var storedHash string
	err = d.db.QueryRow("SELECT password FROM users WHERE email = ?", email).Scan(&storedHash)
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

func (d *Database) DeleteUserById() {
	_, err := d.db.Exec("delete from base_crud_bd.users where id = ?;")
	if err != nil {
		log.Println(err)
	}
}
