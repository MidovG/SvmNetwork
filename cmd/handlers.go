package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"svm/internal/entity/userModel"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func RenderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("../templates/html/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func RenderStaticFiles(router *mux.Router) {
	staticFileDirectory := http.FileServer(http.Dir("../templates"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", staticFileDirectory))
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "practice_page.html", nil)
}

func AboutUsPage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "about_us.html", nil)
}

func SignPage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "lk.html", nil)
}

func Personal_Lk(w http.ResponseWriter, r *http.Request) {
	if userModel.IsValidToken(r) {
		userId := userModel.GetIdFromJWT(r)

		if userId == 0 {
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
			return
		}

		userProfiles := gDatabase.LoadPersonalInfo(userId)
		RenderTemplate(w, "dashboard.html", userProfiles)
	} else {
		http.Redirect(w, r, "/sign_page", http.StatusSeeOther)
	}

}

func PasswordPage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "password_page.html", nil)
}

func UpdatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		log.Println("Неверный запрос")
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	oldPassword := r.FormValue("old-password")
	newPassword := r.FormValue("new-password")
	confirmPassword := r.FormValue("confirm-password")

	userId := userModel.GetIdFromJWT(r)

	if userId == 0 {
		http.Redirect(w, r, "/user_password", http.StatusBadRequest)
		return
	}

	truePassword := gDatabase.CheckPasswordById(userId, oldPassword)

	if !truePassword {
		log.Println("Старые пароли не совпадают")
		http.Redirect(w, r, "/user_password", http.StatusBadRequest)
		return
	}

	fmt.Println(newPassword)
	fmt.Println(confirmPassword)
	if newPassword != confirmPassword {
		log.Println("Новые пароли не совпадают")
		http.Redirect(w, r, "/user_password", http.StatusBadRequest)
		return
	}

	hashedPassword, errOfHashed := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

	if errOfHashed != nil {
		log.Println("Ошибка при хешировании", errOfHashed)
		http.Redirect(w, r, "/user_password", http.StatusBadRequest)
		return
	}

	errOfUpdatingPassword := gDatabase.UpdateUserPassword(hashedPassword, userId)

	if errOfUpdatingPassword != nil {
		http.Redirect(w, r, "/user_password", http.StatusBadRequest)
		return
	}

	log.Println("Пароль успешно изменён")
	http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
}

func Autorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		log.Println("Неверный запрос")
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	isExist := gDatabase.CheckExist(email)

	if isExist {
		isCompare := gDatabase.CheckPassword(email, password)

		if isCompare {

			userId := gDatabase.GetUserId(email)

			if userId == 0 {
				log.Println("Ошибка получения id пользователя")
			}

			tokenString, errToken := userModel.CreateJWTToken(userId)

			if errToken != nil && tokenString != "" {
				log.Println("Ошибка формирования токена: ", errToken)
			}

			userModel.SetUserCookie(w, r, tokenString)

			time.Sleep(100 * time.Millisecond)
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/sign_page", http.StatusBadRequest)
		}

	} else {
		log.Println("Пользователь с таким email не существует")
	}

}

func Registration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		log.Println("Неверный запрос")
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse from", http.StatusBadRequest)
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	isExist := gDatabase.CheckExist(email)

	if isExist {
		log.Println("Пользователь с таким email уже существует")
	} else {
		errOfAdding := gDatabase.AddNewUser(name, email, password)

		if errOfAdding != nil {
			log.Println("Произошла ошибка при добавлении пользователя: ", errOfAdding)
			http.Redirect(w, r, "/sign_page", http.StatusBadRequest)
		} else {
			log.Println("Пользователь успешно добавлен!")
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
		}
	}

}

func SavePersonalInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		log.Println("Неверный запрос")
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse from", http.StatusBadRequest)
	}

	first_name := r.FormValue("first_name")
	last_name := r.FormValue("last_name")
	email := r.FormValue("email")

	userId := userModel.GetIdFromJWT(r)

	personalInfoExist := gDatabase.CheckExistPersonalInfo(userId)

	if !personalInfoExist {
		errOfAddingPersonalInfo := gDatabase.AddPersonalInfo(first_name, last_name, email, userId)

		if errOfAddingPersonalInfo != nil {
			log.Println(errOfAddingPersonalInfo)
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
			return
		} else {
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
			return
		}

	} else {
		if userId == 0 {
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
			return
		}

		errOfSavingPersonalInfo := gDatabase.UpdatePersonalInfo(first_name, last_name, email, userId)

		if errOfSavingPersonalInfo != nil {
			log.Println("Произошла ошибка при сохранении персональных данных пользователя: ", errOfSavingPersonalInfo)
			http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
		}

		log.Println("Персональные данные пользователя успешно сохранены!")
		http.Redirect(w, r, "/personal_lk", http.StatusSeeOther)
		return
	}
}

func ExitFromLk(w http.ResponseWriter, r *http.Request) {
	userModel.ResetUserCookie(w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
