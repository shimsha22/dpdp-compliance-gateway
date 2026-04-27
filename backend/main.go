package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/rs/cors"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/secure", secureTextHandler)
	mux.HandleFunc("/api/secure-image", secureImageHandler)
	mux.HandleFunc("/api/secure-csv", secureCSVHandler)
	mux.HandleFunc("/api/verify-audit", verifyAuditHandler)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"https://vigilant-vault.onrender.com",
			"http://localhost:5173",
		},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	handler := c.Handler(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Vigilant-Vault API is fully online on http://localhost:%s\n", port)
	fmt.Println("Press Ctrl+C in the terminal to stop the server.")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal("Server crashed:", err)
	}
}
