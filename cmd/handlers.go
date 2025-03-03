package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
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
	RenderTemplate(w, "main_page.html", nil)
}

func NetworkInfo(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "network_traffic.html", nil)
}

func AnomaliesInfo(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "anomalies.html", nil)
}

func AboutUsPage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "about_us.html", nil)
}

func PracticePage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "practice_page.html", nil)
}

func SignPage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "lk.html", nil)
}

func Personal_Lk(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "dashboard.html", nil)
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
