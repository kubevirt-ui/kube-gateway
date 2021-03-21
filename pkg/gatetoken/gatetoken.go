package gatetoken

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	ocgatev1beta1 "github.com/yaacov/oc-gate-operator/api/v1beta1"
)

// Server holds information required for serving files.
type Server struct {
	APIServerURL string
	APITransport *http.Transport
}

// GataToken handle callbacs from OAuth2 authtorization server.
func (s Server) GataToken(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	// Check request method, we only allow post requests.
	if r.Method != http.MethodPost {
		handleError(w, fmt.Errorf("%s is not allowed", r.Method))
		return
	}

	// Get bearer token from request
	bearer, err := GetRequestBearerToken(r)
	if err != nil {
		handleError(w, fmt.Errorf("fail to get authorization: %+v", err))
		return
	}

	// Create an empty gate token
	gateToken := &ocgatev1beta1.GateToken{
		Status: ocgatev1beta1.GateTokenStatus{
			Phase: "Error",
		},
	}

	// Parse request body as gate token spec
	if err := json.NewDecoder(r.Body).Decode(&gateToken); err != nil {
		handleError(w, fmt.Errorf("fail to parse token request: %+v", err))
		return
	}

	// Cache token data in the spec section
	cacheData(gateToken)

	// Get private key secret for signing JWT
	privateKeyBytes, err := s.getPrivateKey(gateToken.Namespace, bearer)
	if err != nil {
		handleError(w, fmt.Errorf("secret error: %+v", err))
		return
	}

	// Sign the token
	if err := singToken(gateToken, privateKeyBytes); err != nil {
		handleError(w, fmt.Errorf("fail to sign token: %+v", err))
		return
	}

	// Return a signed token as a JSON struct
	b, err := json.Marshal(gateToken)
	if err != nil {
		handleError(w, fmt.Errorf("fail to marshal token: %+v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"kind\": \"Status\", \"api\": \"ocgate\", \"status\": \"Forbidden\", \"message\": \"%s\",\"code\": %d}", err, http.StatusForbidden)
}

// GetRequestBearerToken parses a request and get the token to pass to k8s API
func GetRequestBearerToken(r *http.Request) (string, error) {
	// Check for Authorization HTTP header
	if authorization := r.Header.Get("Authorization"); len(authorization) > 7 && authorization[:7] == "Bearer " {
		return authorization[7:], nil
	}

	return "", fmt.Errorf("faile to read authorization header")
}
