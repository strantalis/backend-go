package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func LoadEntitlementRoutes() chi.Router {
	r := chi.NewRouter()
	r.Route("/entitlements", func(r chi.Router) {
		r.Route("/entitlements", func(r chi.Router) {
			r.Get("/", getEntitlements)
			r.Post("/{entityId}", addEntitlement)
			r.Delete("/{entityId}", removeEntitlement)
		})
	})
	return r
}

func getEntitlements(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func addEntitlement(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func removeEntitlement(w http.ResponseWriter, r *http.Request) {
	// TODO
}
