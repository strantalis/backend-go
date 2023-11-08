package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/opentdf/backend-go/internal/db"
	"github.com/opentdf/backend-go/pkg/entitlements"
)

type entClient struct {
	entitlements.Client
}

func LoadEntitlementRoutes(db *db.Client) chi.Router {
	ent := entitlements.NewClient(db)
	e := entClient{ent}
	r := chi.NewRouter()
	r.Route("/", func(r chi.Router) {
		r.Route("/entitlements", func(r chi.Router) {
			r.Get("/", e.getEntitlements)
			r.Post("/{entityId}", e.addEntitlement)
			r.Delete("/{entityId}", e.removeEntitlement)
		})
	})
	return r
}

func (e entClient) getEntitlements(w http.ResponseWriter, r *http.Request) {
	var entArr []interface{}
	entityID := r.URL.Query().Get("entityId")
	ent, err := e.GetEntitlements(entityID)
	if err != nil {
		slog.Error("could not retrieve entitlements", err)
		http.Error(w, "could not retrieve entitlements", http.StatusInternalServerError)
		return
	}
	entArr = append(entArr, ent)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(entArr)
}

func (e entClient) addEntitlement(w http.ResponseWriter, r *http.Request) {
	entitID := chi.URLParam(r, "entityId")
	var attr []string
	err := json.NewDecoder(r.Body).Decode(&attr)
	if err != nil {
		slog.Error("could not decode entitlement", err)
		http.Error(w, "could not decode entitlement", http.StatusBadRequest)
		return
	}
	_, err = e.AddEntitlement(entitID, attr)
	if err != nil {
		slog.Error("could not add entitlement", err)
		http.Error(w, "could not add entitlement", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attr)
}

func (e entClient) removeEntitlement(w http.ResponseWriter, r *http.Request) {
	entitID := chi.URLParam(r, "entityId")
	var attr []string
	err := json.NewDecoder(r.Body).Decode(&attr)
	if err != nil {
		slog.Error("could not decode entitlement", err)
		http.Error(w, "could not decode entitlement", http.StatusBadRequest)
		return
	}
	err = e.RemoveEntitlement(entitID, attr)
	if err != nil {
		slog.Error("could not remove entitlement", err)
		http.Error(w, "could not remove entitlement", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
