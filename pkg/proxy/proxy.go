package proxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const (
	ocproxySessionCookieName = "ocproxy-session-token"
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
}

// Login redirects to OAuth2 authtorization login endpoint.
func (s Server) Login(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

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
		Name:     ocproxySessionCookieName,
		Value:    tok.AccessToken,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

// AuthMiddleware will look for a seesion cookie and use it as a Bearer token.
func (s Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request
		log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		// Check for session cookie
		cookie, err := r.Cookie(ocproxySessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, s.LoginEndpoint, http.StatusTemporaryRedirect)
			return
		}

		// Set Authorization header
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cookie.Value))
		next.ServeHTTP(w, r)
	})
}

// Proxy return a Handler func that will proxy request to k8s API.
func (s Server) Proxy() http.Handler {
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