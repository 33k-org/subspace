package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	httprouter "github.com/julienschmidt/httprouter"
)

// apiJSON writes v as a JSON response with the given status code.
func apiJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			logger.Errorf("api: encoding response failed: %s", err)
		}
	}
}

// apiError writes a JSON error response of the form {"error": "..."}.
func apiError(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}

// APIHandler wraps an API endpoint with bearer-token authentication. The token
// is configured by an admin from the settings page and stored in config.json.
// When no token is configured the API is disabled entirely.
func APIHandler(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		token := config.FindInfo().APIToken
		if token == "" {
			apiError(w, http.StatusForbidden, "api is disabled: no token configured")
			return
		}

		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			apiError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}

		provided := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			apiError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		h(w, r, ps)
	}
}

// apiListUsers returns all users as JSON.
func apiListUsers(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	apiJSON(w, http.StatusOK, config.ListUsers())
}

// apiAddUser creates a user from a JSON body {"email": "...", "admin": false}.
// It is idempotent: an existing user with the same email is returned unchanged
// except that admin may be promoted when "admin": true is supplied.
func apiAddUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var req struct {
		Email string `json:"email"`
		Admin bool   `json:"admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		apiError(w, http.StatusBadRequest, "email is required")
		return
	}

	user, err := config.AddUser(email)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.Admin && !user.Admin {
		if err := config.UpdateUser(user.ID, func(u *User) error {
			u.Admin = true
			return nil
		}); err != nil {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		user, _ = config.FindUser(user.ID)
	}

	apiJSON(w, http.StatusOK, user)
}

// apiDeleteUser deletes the user identified by the :user path parameter along
// with all of their WireGuard profiles (peers), mirroring the GUI behaviour.
func apiDeleteUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := config.FindUser(ps.ByName("user"))
	if err != nil {
		apiError(w, http.StatusNotFound, "user not found")
		return
	}

	for _, profile := range config.ListProfilesByUser(user.ID) {
		if err := deleteProfile(profile); err != nil {
			apiError(w, http.StatusInternalServerError, "failed to delete profile: "+err.Error())
			return
		}
	}

	if err := config.DeleteUser(user.ID); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
