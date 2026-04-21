package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/api/secure", secureTextHandler)
	http.HandleFunc("/api/secure-image", secureImageHandler)
	http.HandleFunc("/api/secure-csv", secureCSVHandler)

	fmt.Println(" Vigilant-Vault API is fully online on http://localhost:8080")
	fmt.Println("Press Ctrl+C in the terminal to stop the server.")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server crashed:", err)
	}
}
