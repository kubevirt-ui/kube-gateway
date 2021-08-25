package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Endpoint holds the API server authorization URL.
type Endpoint struct {
	Auth  string `json:"authorization_endpoint"`
	Token string `json:"token_endpoint"`
}

// GetServerEndpoint gets the API server well known oauth authorization endpoints.
func GetServerEndpoint(serverURL string, transport *http.Transport) (Endpoint, error) {
	var endpoint Endpoint
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	wellKnownURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", serverURL)
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return endpoint, fmt.Errorf("fail to get well-known oauth-authorization-server: %+v", err)
	}

	if err := json.NewDecoder(resp.Body).Decode(&endpoint); err != nil {
		return endpoint, fmt.Errorf("fail to get well known authorization endpoints: %+v", err)
	}

	return endpoint, nil
}
