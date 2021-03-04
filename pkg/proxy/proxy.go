package proxy

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

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

// Token handle callbacs from OAuth2 authtorization server.
func (s Server) Token(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	q := r.URL.Query()
	token := q.Get("token")
	redirect := q.Get("redirect")

	// Empty redirect, means go home
	if redirect == "" {
		redirect = "/"
	}

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ocgateSessionCookieName,
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true})
	http.Redirect(w, r, redirect, http.StatusFound)
}

// AuthMiddleware will look for a seesion cookie and use it as a Bearer token.
func (s Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request
		log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		// Get request token from Authorization header and session cookie
		token, _ := s.GetRequestToken(w, r)

		// If using interactive login and no token, redirect user to login endpoint
		if s.InteractiveAuth && token == "" {
			http.Redirect(w, r, s.LoginEndpoint, http.StatusTemporaryRedirect)
			return
		}

		// If using non interactive login and noe token, send an error.
		if token == "" {
			handleError(w, fmt.Errorf("no token received"))
			return
		}

		// If using token pass through, continue with user token
		if s.BearerTokenPassthrough {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			next.ServeHTTP(w, r)
			return
		}

		// If static path, skip token validation
		if len(r.URL.Path) <= len(s.APIPath) || r.URL.Path[:len(s.APIPath)] != s.APIPath {
			next.ServeHTTP(w, r)
			return
		}

		// If not using token passthrogh validate JWT token
		// and replace the token with the k8s access token
		_, err := validateToken(token, s.JWTTokenKey, s.JWTTokenRSAKey, s.APIPath, r.Method, r.URL.Path)
		if err != nil {
			handleError(w, err)
			return
		}

		// If user token is validated, send request using the operator token
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

// GetRequestToken parses a request and get the token to pass to k8s API
func (s Server) GetRequestToken(w http.ResponseWriter, r *http.Request) (string, error) {
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
