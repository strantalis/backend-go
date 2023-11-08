/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/opentdf/backend-go/api"
	"github.com/opentdf/backend-go/api/middleware/auth"
	"github.com/opentdf/backend-go/internal/db"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start OpenTDF Core Services",
	Run:   start,
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func start(cmd *cobra.Command, args []string) {
	// Lets make sure we can establish a new db client
	dbClient, err := db.NewClient(os.Getenv("DB_URL"))
	if err != nil {
		slog.Error("could not establish database connection", err)
		os.Exit(1)
	}

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.OidcAuth("https://platform.shp.virtru.us/auth/realms/virtru/protocol/openid-connect/certs"))
		r.Route("/api", func(r chi.Router) {
			r.Mount("/attributes", api.LoadAttributeRoutes(dbClient))
			r.Mount("/entitlements", api.LoadEntitlementRoutes(dbClient))
		})
	})
	r.Route("/healthz", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	server := &http.Server{
		Addr:    ":8081",
		Handler: r,
	}

	stopChan := make(chan os.Signal, 1)

	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Start the HTTP server in a goroutine
	go func() {
		// If ListenAndServe returns an error and it's not a server closed error,
		// then log it as a fatal error.
		slog.Info("Starting server on port 8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("ListenAndServe(): ", err)
		}
	}()

	<-stopChan
	slog.Info("Shutting down server...")

	// Create a context with a 15-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	// Make sure to cancel the context when done
	defer cancel()

	// Initiate graceful shutdown
	// If it doesn't complete in 15 seconds, it will be forcefully stopped
	if err := server.Shutdown(ctx); err != nil {
		// Log if the shutdown failed
		slog.Error("Server Shutdown Failed: ", err)
		os.Exit(1)
	} else {
		// Log that the server has stopped gracefully
		slog.Info("Server stopped gracefully")
	}

}
