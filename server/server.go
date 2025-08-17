package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

// StartServer starts an HTTP server on port 8080 and handles graceful shutdown.
func StartServer(ctx context.Context) {
	// Create a new HTTP server instance.
	server := &http.Server{Addr: ":8080"}

	// Register a handler for all incoming requests.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Log the incoming request method and URL.
		log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		// Send a simple response to the client.
		fmt.Fprint(w, "Hello from the server!")
	})

	// Start the server in a separate goroutine.
	go func() {
		fmt.Println("Starting server on http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("could not start server: %v", err)
		}
	}()

	// Wait for the context to be canceled.
	<-ctx.Done()
	log.Println("Shutting down server...")

	// Create a shutdown context with a timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt to gracefully shut down the server.
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("Server gracefully stopped")
}
