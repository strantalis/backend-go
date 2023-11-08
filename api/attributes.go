package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/opentdf/backend-go/internal/db"
	"github.com/opentdf/backend-go/pkg/attributes"
)

type attrClient struct {
	attributes.Client
}

func LoadAttributeRoutes(db *db.Client) chi.Router {
	attr := attributes.NewClient(db)
	a := attrClient{attr}
	r := chi.NewRouter()
	r.Route("/", func(r chi.Router) {
		r.Get("/attributes", a.getAttributes)

		//Authorities
		r.Get("/authorities", a.getAuthorities)
		r.Post("/authorities", a.createAuthority)
		r.Delete("/authorities", a.deleteAuthority)

		//Definitions
		r.Get("/definitions/attributes", a.getDefinitions)
		r.Post("/definitions/attributes", a.createDefinition)
		r.Put("/definitions/attributes", a.updateDefinition)
		r.Delete("/definitions/attributes", a.deleteDefinition)
	})
	return r
}

func (a attrClient) getAttributes(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func (a attrClient) getAuthorities(w http.ResponseWriter, r *http.Request) {
	authorities, err := a.Client.GetAuthorities()
	if err != nil {
		slog.Error("could not retrieve authorities", err)
		http.Error(w, "could not retrieve authorities", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authorities)
}

func (a attrClient) createAuthority(w http.ResponseWriter, r *http.Request) {
	var authority map[string]string
	err := json.NewDecoder(r.Body).Decode(&authority)
	if err != nil {
		slog.Error("could not decode authority", err)
		http.Error(w, "could not decode authority", http.StatusBadRequest)
		return
	}
	if _, ok := authority["authority"]; !ok {
		slog.Error("authority name not provided")
		http.Error(w, "authority name not provided", http.StatusBadRequest)
		return
	}
	err = a.Client.CreateAuthority(authority["authority"])
	if err != nil {
		slog.Error("could not create authority", err)
		http.Error(w, "could not create authority", http.StatusInternalServerError)
		return
	}
	authorities, err := a.Client.GetAuthorities()
	if err != nil {
		slog.Error("could not retrieve authorities", err)
		http.Error(w, "could not retrieve authorities", http.StatusInternalServerError)
		return
	}
	// Why are we returning the authorities here on create?
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authorities)
	//w.WriteHeader(http.StatusCreated)
}

func (a attrClient) deleteAuthority(w http.ResponseWriter, r *http.Request) {
	var authority map[string]string
	err := json.NewDecoder(r.Body).Decode(&authority)
	if err != nil {
		slog.Error("could not decode authority", err)
		http.Error(w, "could not decode authority", http.StatusBadRequest)
		return
	}
	if _, ok := authority["authority"]; !ok {
		slog.Error("authority name not provided")
		http.Error(w, "authority name not provided", http.StatusBadRequest)
		return
	}
	err = a.Client.DeleteAuthority(authority["authority"])
	if err != nil {
		slog.Error("could not delete authority", err)
		http.Error(w, "could not delete authority", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a attrClient) getDefinitions(w http.ResponseWriter, r *http.Request) {
	authority := r.URL.Query().Get("authority")

	attributes, err := a.Client.GetAttributes(authority)
	if err != nil {
		slog.Error("could not retrieve attributes", err)
		http.Error(w, "could not retrieve attributes", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(attributes)
}

func (a attrClient) createDefinition(w http.ResponseWriter, r *http.Request) {
	var attr attributes.Attribute
	err := json.NewDecoder(r.Body).Decode(&attr)
	if err != nil {
		slog.Error("could not decode attribute", err)
		http.Error(w, "could not decode attribute", http.StatusBadRequest)
		return
	}
	_, err = a.Client.CreateDefinition(attr)
	if err != nil {
		slog.Error("could not create attribute", err)
		http.Error(w, "could not create attribute", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attr)
}

func (a attrClient) updateDefinition(w http.ResponseWriter, r *http.Request) {
	var attr attributes.Attribute
	err := json.NewDecoder(r.Body).Decode(&attr)
	if err != nil {
		slog.Error("could not decode attribute", err)
		http.Error(w, "could not decode attribute", http.StatusBadRequest)
		return
	}
	_, err = a.Client.UpdateDefinition(attr)
	if err != nil {
		slog.Error("could not update attribute", err)
		http.Error(w, "could not update attribute", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attr)
}

func (a attrClient) deleteDefinition(w http.ResponseWriter, r *http.Request) {
	var attr attributes.Attribute
	err := json.NewDecoder(r.Body).Decode(&attr)
	if err != nil {
		slog.Error("could not decode attribute", err)
		http.Error(w, "could not decode attribute", http.StatusBadRequest)
		return
	}
	err = a.Client.DeleteDefinition(attr.Authority, attr.Name)
	if err != nil {
		slog.Error("could not delete attribute", err)
		http.Error(w, "could not delete attribute", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	w.Header().Set("Content-Type", "application/json")

}
