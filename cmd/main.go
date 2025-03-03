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

	// info pages
	r.HandleFunc("/anomalies", AnomaliesInfo).Methods("POST", "GET")
	r.HandleFunc("/network", NetworkInfo).Methods("POST", "GET")
	r.HandleFunc("/about_us", AboutUsPage).Methods("POST", "GET")

	// practice
	r.HandleFunc("/practice", PracticePage).Methods("POST", "GET")

	RenderStaticFiles(r)

	fmt.Println("Server is listening...")
	http.ListenAndServe(":8181", r)
}
