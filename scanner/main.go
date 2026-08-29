package main

import(
	"log"
	"net/http"
)

func main(){
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/scan/tls", tlsHandler)
	http.HandleFunc("/scan/headers", headersHandler)
	http.HandleFunc("/scan/email", emailHandler)

	log.Println("scanner service listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}