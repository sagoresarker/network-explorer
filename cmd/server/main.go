package main

import (
	"log"
	"net/http"
	"time"

	"github.com/sagoresarker/network-explorer/internal/handlers"
)

func main() {
	tracerouteHandler := handlers.NewTracerouteHandler()
	healthHandler := handlers.NewHealthHandler()
	journeyHandler := handlers.NewJourneyHandler()

	http.HandleFunc("/health", healthHandler.Handle)
	http.HandleFunc("/traceroute", handlers.EnableCORS(tracerouteHandler.Handle))
	http.HandleFunc("/journey", handlers.EnableCORS(journeyHandler.Handle))

	server := &http.Server{
		Addr:         ":8090",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
	}

	log.Println("Server is running on http://localhost:8090")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
