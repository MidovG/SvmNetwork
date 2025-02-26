package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	defer gDatabase.Close()

	r := mux.NewRouter()

	r.HandleFunc("/", HomePage)

	r.HandleFunc("/autorization", Autorization).Methods("POST")

	RenderStaticFiles(r)

	fmt.Println("server is listening...")
	http.ListenAndServe(":8181", r)
}
