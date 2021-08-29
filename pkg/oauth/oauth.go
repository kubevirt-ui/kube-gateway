package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	// CookieName is used in web browser to store the berear token recived from
	// the OAuth2 server.
	CookieName = "kg-bearer-session-code"
)

// OAuth holds information required for serving files.
type OAuth struct {
	APITransport *http.Transport
	Auth2Config  *oauth2.Config
}

// Login redirects to OAuth2 authtorization login endpoint.
func (o OAuth) Login(w http.ResponseWriter, r *http.Request) {
	// Log request
	glog.Infof("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	id := uuid.New()

	conf := o.Auth2Config
	authURL := conf.AuthCodeURL(id.String(), oauth2.AccessTypeOnline, oauth2.ApprovalForce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Logout redirects to OAuth2 authtorization Logout endpoint.
func (o OAuth) Logout(w http.ResponseWriter, r *http.Request) {
	logoutURL := "/"

	// Log request
	glog.Infof("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	u, err := url.Parse(o.Auth2Config.Endpoint.AuthURL)
	if err == nil {
		logoutURL = fmt.Sprintf("%s://%s/logout", u.Scheme, u.Host)
	}

	glog.Infof("logoutURL: %s", logoutURL)

	http.Redirect(w, r, logoutURL, http.StatusFound)
}

// Callback handle callbacs from OAuth2 authtorization server.
func (o *OAuth) Callback(w http.ResponseWriter, r *http.Request) {
	// Log request
	glog.Infof("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	ctx := context.Background()

	q := r.URL.Query()
	code := q.Get("code")

	// Use the custom HTTP client when requesting a token.
	httpClient := &http.Client{Transport: o.APITransport, Timeout: 2 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	conf := o.Auth2Config
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    tok.AccessToken,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}
