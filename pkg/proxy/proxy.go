package proxy

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/golang/glog"

	"github.com/kubevirt-ui/kube-gateway/pkg/oauth"
	"github.com/kubevirt-ui/kube-gateway/pkg/token"
)

// Server holds information required for serving files.
type Server struct {
	APIPath     string
	BaseAddress string

	APIServerURL string
	APITransport *http.Transport
	BearerToken  string

	JWTTokenRSAKey *rsa.PublicKey

	OAuthServer *oauth.OAuth
}

// AuthMiddleware will look for a seesion cookie and use it as a Bearer token.
func (s Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request
		glog.Infof("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		// Check for none API calls
		httpPath := r.URL.Path
		if len(httpPath) <= len(s.APIPath) || httpPath[:len(s.APIPath)] != s.APIPath ||
			httpPath[len(s.APIPath):] == ".well-known/oauth-authorization-server" {
			next.ServeHTTP(w, r)

			return
		}

		// If we are using OAuth2 server, try to use the bearer code cookie
		if s.OAuthServer != nil {
			s.AddCodeAuthentication(next, w, r)
			return
		}

		// If we are using OAuth2 server, try to use the bearer code cookie
		if s.JWTTokenRSAKey != nil {
			s.AddJWTAuthentication(next, w, r)
			return
		}

		handleError(w, fmt.Errorf("missing JWT public key and/or OAuth2, can't access k8s API server"))
	})
}

// APIProxy return a Handler func that will proxy request to k8s API.
func (s Server) APIProxy() http.Handler {
	// Parse the url
	url, _ := url.Parse(s.APIServerURL)

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = s.APITransport

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Update the headers to allow for SSL redirection
			r.URL.Host = url.Host
			r.URL.Scheme = url.Scheme
			r.URL.Path = r.URL.Path[len(s.APIPath)-1:]

			// Log proxy request
			glog.Infof("%s %v: [PROXY] %+v", r.RemoteAddr, r.Method, r.URL)

			// Call server
			proxy.ServeHTTP(w, r)
		})
}

// AddCodeAuthentication adds the bearer authentication header to the http request and proxy
// it to the api server using OAuth2 server token
func (s Server) AddCodeAuthentication(next http.Handler, w http.ResponseWriter, r *http.Request) {
	// Get request token from Authorization header and session cookie
	code, _ := s.GetRequestAuthCode(w, r)

	// If we have an authentication code from OAuth server, use it
	if code != "" {
		// If user token is validated, send request using the operator token
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", code))
		next.ServeHTTP(w, r)

		return
	}

	handleError(w, fmt.Errorf("request is missing bearer token code, try to re login"))
}

// AddJWTAuthentication adds the bearer authentication header to the http request and proxy
// it to the api server using JWT authentication
func (s Server) AddJWTAuthentication(next http.Handler, w http.ResponseWriter, r *http.Request) {
	httpPath := r.URL.Path

	// Get request token from Authorization header and session cookie
	tokenStr, _ := s.GetRequestToken(w, r)

	// If using non interactive login and noe token, send an error.
	if tokenStr != "" {
		// If not using token passthrogh validate JWT token
		// and replace the token with the k8s access token
		_, err := token.ValidateToken(tokenStr, s.JWTTokenRSAKey, s.APIPath, r.Method, httpPath[len(s.APIPath)-1:])
		if err != nil {
			handleError(w, err)

			return
		}

		// If user token is validated, send request using the operator token
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.BearerToken))
		next.ServeHTTP(w, r)

		return
	}

	handleError(w, fmt.Errorf("request is missing JWT code, set the session JWT code and try again"))
}

// GetRequestToken parses a request and get the token to pass to k8s API
func (s Server) GetRequestToken(w http.ResponseWriter, r *http.Request) (string, error) {
	// Check for session cookie
	cookie, err := r.Cookie(token.CookieName)
	if err != nil || cookie.Value == "" {
		return "", err
	}
	return cookie.Value, nil
}

// GetRequestAuthCode parses a request and get the token to pass to k8s API
func (s Server) GetRequestAuthCode(w http.ResponseWriter, r *http.Request) (string, error) {
	// Check for session cookie
	cookie, err := r.Cookie(oauth.CookieName)
	if err != nil || cookie.Value == "" {
		return "", err
	}
	return cookie.Value, nil
}

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
