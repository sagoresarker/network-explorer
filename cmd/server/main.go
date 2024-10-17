package main

import (
	"log"
	"net/http"
	"time"

	"github.com/sagoresarker/traceroute-go-portfolio/internal/handlers"
)

func main() {
	tracerouteHandler := handlers.NewTracerouteHandler()
	healthHandler := handlers.NewHealthHandler()

	http.HandleFunc("/health", healthHandler.Handle)
	http.HandleFunc("/traceroute", handlers.EnableCORS(tracerouteHandler.Handle))

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
	}

	log.Println("Server is running on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
