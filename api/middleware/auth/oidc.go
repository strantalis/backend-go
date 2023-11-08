package auth

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func startJWKCache(wellknown string) (*jwk.Cache, error) {
	ctx := context.Background()

	c := jwk.NewCache(ctx)
	c.Register(wellknown, jwk.WithMinRefreshInterval(15*time.Minute))
	_, err := c.Refresh(ctx, wellknown)
	if err != nil {
		return nil, err
	}
	slog.Info("jwk cache started")
	return c, nil
}

func OidcAuth(wellknown string) func(next http.Handler) http.Handler {
	c, err := startJWKCache(wellknown)
	if err != nil {
		panic(err)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keyset, err := c.Get(r.Context(), wellknown)
			if err != nil {
				slog.Error("could not retrieve keyset", err)
				http.Error(w, "internal server error validating authorization header", http.StatusInternalServerError)
				return
			}
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}
			_, err = jwt.ParseString(authHeader[7:], jwt.WithKeySet(keyset))
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
			if jwt.IsValidationError(err) {
				slog.Error("jwt could not be validated", err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			slog.Error("jwt could not be parsed", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		})
	}
}
