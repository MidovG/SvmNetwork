package main

import (
	"html/template"
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

func Autorization(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "lk.html", nil)

	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	email := r.Form.Get("email")
	password := r.Form.Get("password")

	ok, err := gDatabase.CheckUserForLogin(email, password)

	if ok && err != nil {
		RenderTemplate(w, "dashboard.html", nil)
	} else {
		RenderTemplate(w, "home_page.html", nil)
	}
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "home_page.html", nil)
}
