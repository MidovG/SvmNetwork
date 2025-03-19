package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	defer gDatabase.Close()

	r := mux.NewRouter()

	// start page
	r.HandleFunc("/", HomePage)

	// sign
	r.HandleFunc("/sign_page", SignPage).Methods("POST", "GET")
	r.HandleFunc("/sign_in", Autorization).Methods("POST", "GET")
	r.HandleFunc("/sign_up", Registration).Methods("POST", "GET")

	// personal info
	r.HandleFunc("/personal_lk", Personal_Lk).Methods("POST", "GET")
	r.HandleFunc("/save_dat", SavePersonalInfo).Methods("POST", "GET")
	r.HandleFunc("/user_password", PasswordPage).Methods("POST", "GET")
	r.HandleFunc("/update_password", UpdatePassword).Methods("POST", "GET")
	r.HandleFunc("/exit", ExitFromLk).Methods("POST", "GET")

	// info pages
	r.HandleFunc("/about_us", AboutUsPage).Methods("POST", "GET")

	RenderStaticFiles(r)

	fmt.Println("Server is listening...")
	http.ListenAndServe(":8181", r)
}
