package main

import (
	"fmt"
	"html/template"
	"net/http"
	"svm/internal/repo"

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
	RenderTemplate(w, "home_page.html", nil)
}

func Autorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		RenderTemplate(w, "lk.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	ok, err := gDatabase.CheckUserForLogin(email, password)

	if ok && err == nil {
		RenderTemplate(w, "dashboard.html", nil)

		id, errOfGetId := gDatabase.GetUserId(email)

		if errOfGetId != nil {
			fmt.Println(errOfGetId)
		} else {
			tokenString, errOfCreateJWT := repo.CreateJWTToken(id)

			if errOfCreateJWT != nil {
				fmt.Println(errOfCreateJWT)
			} else {
				errOfCreateSession := gDatabase.CreateSession(id, tokenString)

				if errOfCreateSession != nil {
					fmt.Println(errOfCreateSession)
				}
			}
		}
	} else {
		RenderTemplate(w, "home_page.html", nil)
	}
}

func Registration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		RenderTemplate(w, "lk.html", nil)
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse from", http.StatusBadRequest)
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	ok, err := gDatabase.AddNewUser(name, email, password)
	if ok && err == nil {
		RenderTemplate(w, "dashboard.html", nil)
	} else {
		RenderTemplate(w, "home_page.html", nil)
	}

}
