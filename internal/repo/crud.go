package repo

import (
	"log"
	"svm/internal/entity/userModel"
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

func (d *Database) CheckPasswordById(userId int, password string) bool {
	var password_hash string
	err := d.db.QueryRow("select password_hash from svm_network.users where id = ?", userId).Scan(&password_hash)

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

func (d *Database) DeleteUserById(userId int) error {
	_, errOfDel := d.db.Exec("delete from svm_network.users where id = ?", userId)

	if errOfDel != nil {
		log.Println(errOfDel)
		return errOfDel
	}

	return nil
}

func (d *Database) AddPersonalInfo(first_name, last_name, email string, userId int) error {
	_, errProfiles := d.db.Exec("insert into svm_network.user_profiles(user_id, first_name, last_name) values(?,?,?)", userId, first_name, last_name)

	if errProfiles != nil {
		log.Println(errProfiles)
		return errProfiles
	}

	return nil
}

func (d *Database) UpdatePersonalInfo(first_name, last_name, email string, userId int) error {
	_, errOfUpdating := d.db.Exec("update svm_network.user_profiles set first_name = ?, last_name = ? where user_id = ?", first_name, last_name, userId)

	if errOfUpdating != nil {
		log.Println(errOfUpdating)
		return errOfUpdating
	}

	_, errOfUpdatingEmail := d.db.Exec("update svm_network.users set email = ? where id = ?", email, userId)

	if errOfUpdatingEmail != nil {
		log.Println(errOfUpdatingEmail)
		return errOfUpdatingEmail
	}

	return nil
}

func (d *Database) UpdateUserPassword(newPassword string, userId int) error {
	_, errOfUpdating := d.db.Exec("update svm_network.users set password_hash = ? where id = ?", newPassword, userId)

	if errOfUpdating != nil {
		log.Println(errOfUpdating)
		return errOfUpdating
	}

	return nil
}

func (d *Database) LoadPersonalInfo(userId int) userModel.UserProfile {
	var userProfile userModel.UserProfile
	userProfile.User_Id = userId

	errOfLoading := d.db.QueryRow("select first_name, last_name from svm_network.user_profiles where user_id = ?", userId).Scan(&userProfile.First_Name, &userProfile.Last_Name)

	if errOfLoading != nil {
		log.Println(errOfLoading)
	}

	errOfLoadingSecret := d.db.QueryRow("select email from svm_network.users where id = ?", userId).Scan(&userProfile.Email)

	if errOfLoadingSecret != nil {
		log.Println(errOfLoadingSecret)
	}

	return userProfile
}
