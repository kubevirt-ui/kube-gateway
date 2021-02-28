package proxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
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

	AllowedAPIMethods string
	AllowedAPIRegexp  *regexp.Regexp

	BearerToken            string
	BearerTokenPassthrough bool
	JWTTokenKey            []byte

	OAuthServerDisable bool
}

// Login redirects to OAuth2 authtorization login endpoint.
func (s Server) Login(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ocproxySessionCookieName,
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
		var token string

		// Log request
		log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		// Check for Authorization HTTP header
		if authorization := r.Header.Get("Authorization"); len(authorization) > 7 && authorization[:7] == "Bearer " {
			token = authorization[7:]
		}

		// If bearer authorization is missing and interactive authentication is active
		// check for session cookie
		if token == "" && !s.OAuthServerDisable {
			cookie, err := r.Cookie(ocproxySessionCookieName)
			if err != nil || cookie.Value == "" {
				http.Redirect(w, r, s.LoginEndpoint, http.StatusTemporaryRedirect)
				return
			}
			token = cookie.Value
		}

		// If not using token passthrogh validate JWT token
		// and replace the token with the k8s access token
		if !s.BearerTokenPassthrough && s.BearerToken != "" && token != "" {
			_, err := validateToken(token, s.JWTTokenKey, s.APIPath, r.Method, r.URL.Path)
			if err != nil {
				handleError(w, err)
				return
			}

			token = s.BearerToken
		}

		// Set Authorization header
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
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
			// Verify allowed method and path
			err := validateRequest(r.Method, r.URL.Path, s.APIPath, s.AllowedAPIMethods, s.AllowedAPIRegexp)
			if err != nil {
				handleError(w, err)
				return
			}

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
