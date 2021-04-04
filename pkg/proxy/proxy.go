package proxy

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

const (
	ocgateSessionCookieName = "ocgate-session-token"
)

// Server holds information required for serving files.
type Server struct {
	APIPath      string
	APIServerURL string
	APITransport *http.Transport
	Auth2Config  *oauth2.Config

	BaseAddress    string
	IssuerEndpoint string
	LoginEndpoint  string

	BearerToken            string
	BearerTokenPassthrough bool
	JWTTokenKey            []byte
	JWTTokenRSAKey         *rsa.PublicKey

	InteractiveAuth bool
}

// Login redirects to OAuth2 authtorization login endpoint.
func (s Server) Login(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ocgateSessionCookieName,
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true})

	conf := s.Auth2Config
	url := conf.AuthCodeURL("sessionID", oauth2.AccessTypeOnline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, 302)
}

// Callback handle callbacs from OAuth2 authtorization server.
func (s Server) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	q := r.URL.Query()
	code := q.Get("code")

	// Use the custom HTTP client when requesting a token.
	httpClient := &http.Client{Transport: s.APITransport, Timeout: 2 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	conf := s.Auth2Config
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Printf("fail authentication: %+v", err)
		http.Redirect(w, r, s.LoginEndpoint, http.StatusUnauthorized)
		return
	}

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ocgateSessionCookieName,
		Value:    tok.AccessToken,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

// Token handle manual login requests.
func (s Server) Token(w http.ResponseWriter, r *http.Request) {
	var token string
	var then string

	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	// Get token and redirect from get request
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		token = query.Get("token")
		then = query.Get("then")
	}

	// Get token and redirect from post request
	if r.Method == http.MethodPost {
		token = r.FormValue("token")
		then = r.FormValue("then")
	}

	// Empty redirect, means go home
	if then == "" {
		then = "/"
	}

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ocgateSessionCookieName,
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true})
	http.Redirect(w, r, then, http.StatusFound)
}

// AuthMiddleware will look for a seesion cookie and use it as a Bearer token.
func (s Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request
		log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		// Get request token from Authorization header and session cookie
		token, _ := GetRequestToken(r)

		// Handle interactive authentication
		// If no token, redirect to login endpoint
		if s.InteractiveAuth && token == "" {
			http.Redirect(w, r, s.LoginEndpoint, http.StatusTemporaryRedirect)
			return
		}

		// Handle non-interactive authentication
		// If no token, call an error handler
		if token == "" {
			handleError(w, fmt.Errorf("no token received"))
			return
		}

		// Handle token pass through
		// If token exsit, pass to k8s API directly
		if s.BearerTokenPassthrough {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			next.ServeHTTP(w, r)
			return
		}

		// Get requested static and api paths
		apiPath := strings.Trim(s.APIPath, "/")
		requestPath := strings.Trim(r.URL.Path, "/")
		requestAPIPath := ""
		if len(requestPath) >= len(apiPath) && requestPath[:len(apiPath)] == apiPath {
			requestAPIPath = requestPath[len(apiPath):]
		}

		// Handle white listed paths
		// If a static address or API white listed address, redirect to next without validation
		if requestAPIPath == "" || requestAPIPath == ".well-known/oauth-authorization-server" {
			next.ServeHTTP(w, r)
			return
		}

		// Handle JWT token
		// Validate API path and token
		jwtToken, err := authenticateToken(token, s.JWTTokenKey, s.JWTTokenRSAKey)
		if err != nil || !jwtToken.Valid {
			handleError(w, err)
			return
		}
		if !jwtToken.Valid {
			handleError(w, fmt.Errorf("JWT token is not valid"))
			return
		}

		// Get token claims
		tokenClaims, ok := jwtToken.Claims.(jwt.MapClaims)
		if !ok {
			handleError(w, fmt.Errorf("JWT token claims are not valid"))
			return
		}

		// Authorize API path
		if err := authorizeTokenClamis(tokenClaims, r.Method, requestAPIPath); err != nil {
			handleError(w, err)
			return
		}

		// Handle Valid JWT token
		// send request using the operator token
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.BearerToken))
		next.ServeHTTP(w, r)
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
			log.Printf("%s %v: [PROXY] %+v", r.RemoteAddr, r.Method, r.URL)

			// Call server
			proxy.ServeHTTP(w, r)
		})
}

func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"kind\": \"Status\", \"api\": \"ocgate\", \"status\": \"Forbidden\", \"message\": \"%s\",\"code\": %d}", err, http.StatusForbidden)
}

// GetRequestToken parses a request and get the token to pass to k8s API
func GetRequestToken(r *http.Request) (string, error) {
	// Check for Authorization HTTP header
	if authorization := r.Header.Get("Authorization"); len(authorization) > 7 && authorization[:7] == "Bearer " {
		return authorization[7:], nil
	}

	// Check for session cookie
	cookie, err := r.Cookie(ocgateSessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", err
	}
	return cookie.Value, nil
}
