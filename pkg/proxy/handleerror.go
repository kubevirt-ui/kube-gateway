package proxy

import (
	"encoding/json"
	"net/http"
)

func handleError(w http.ResponseWriter, err error) {
	msg := map[string]interface{}{
		"kind":    "Error",
		"api":     "kube-gateway/proxy",
		"status":  "Forbidden",
		"message": err.Error(),
		"code":    http.StatusForbidden,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(msg)
}
