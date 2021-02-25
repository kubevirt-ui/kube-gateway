package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"golang.org/x/oauth2"
)

const (
	openshiftSessionCookieName = "oc-proxy-session-token"
	authLoginEndpoint          = "/auth/login"
	authLoginCallbackEndpoint  = "/auth/callback"
	errorEndpoint              = "/auth/error"
)

// AuthorizationEndpoint holds the API server authorization URL
type AuthorizationEndpoint struct {
	Issuer string `json:"issuer"`
	Auth   string `json:"authorization_endpoint"`
	Token  string `json:"token_endpoint"`
}

// Server holds information required for serving files.
type Server struct {
	PublicDir     string
	BasePath      string
	APIPath       string
	Listen        string
	BaseAddress   string
	CAFile        string
	SkipVerifyTLS bool
	CertFile      string
	KeyFile       string
	APIServer     string
	ClientID      string
	ClientSecret  string
}

var s = &Server{}

func stateString() string {
	const letters = "0123456789ABCDEF"
	ret := make([]byte, 8)
	for i := 0; i < 8; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			log.Printf("fail to generate state string: %+v", err)
			return ""
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func transport() *http.Transport {
	var transport *http.Transport

	// Add or skip TLS
	if s.SkipVerifyTLS {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		k8sCertPEM, err := ioutil.ReadFile(s.CAFile)
		if err != nil {
			log.Fatalf("Error reading CA file: %v", err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(k8sCertPEM) {
			log.Fatal("No CA found for the API server")
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCAs},
		}
	}

	return transport
}

func oauthServerEndpoint() AuthorizationEndpoint {
	var metadata AuthorizationEndpoint
	client := &http.Client{Transport: transport()}

	wellKnownURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", s.APIServer)
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		log.Printf("fail to get well-known oauth-authorization-server: %+v", err)
		return metadata
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		log.Printf("fail to parse well-known oauth-authorization-server: %+v", err)
		return metadata
	}

	return metadata
}

func oauthConf() *oauth2.Config {
	endpoint := oauthServerEndpoint()

	return &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Scopes:       []string{"user:full"},
		Endpoint: oauth2.Endpoint{
			TokenURL: endpoint.Token,
			AuthURL:  endpoint.Auth,
		},
		RedirectURL: fmt.Sprintf("%s%s", s.BaseAddress, authLoginCallbackEndpoint),
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	conf := oauthConf()

	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	url := conf.AuthCodeURL(stateString(), oauth2.AccessTypeOnline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, 302)
}

func authError(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "something is wrong, please try to login again (%d)", http.StatusInternalServerError)
}

func callback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	conf := oauthConf()
	q := r.URL.Query()
	code := q.Get("code")

	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	// Use the custom HTTP client when requesting a token.
	httpClient := &http.Client{Transport: transport(), Timeout: 2 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Printf("fail authentication: %+v", err)
		http.Redirect(w, r, errorEndpoint, http.StatusUnauthorized)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{Name: openshiftSessionCookieName, Value: tok.AccessToken, Path: "/"})
	http.Redirect(w, r, "/", http.StatusFound)
}

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(openshiftSessionCookieName)

		// Log request
		log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		// Check for session cookie
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, authLoginEndpoint, http.StatusTemporaryRedirect)
			return
		}

		// Set Authorization header
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cookie.Value))
		next.ServeHTTP(w, r)
	})
}

func proxyServer() http.Handler {
	// Parse the url
	url, _ := url.Parse(s.APIServer)

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = transport()

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Update the headers to allow for SSL redirection
			r.URL.Host = url.Host
			r.URL.Scheme = url.Scheme
			r.URL.Path = r.URL.Path[len(s.APIPath)-1:]

			// Log request
			log.Printf("[PROXY] %s %v: %+v", r.RemoteAddr, r.Method, r.URL)

			// Call server
			proxy.ServeHTTP(w, r)
		})
}

func main() {
	var help = false
	flag.BoolVar(&help, "help", false, "print usage.")

	flag.StringVar(&s.PublicDir, "public-dir", "./web", "directory containing static web assets.")
	flag.StringVar(&s.BasePath, "base-path", "/", "server endpoint for static web assets.")

	flag.StringVar(&s.APIServer, "api-server", "", "backend api server.")
	flag.StringVar(&s.APIPath, "api-path", "/api/kubernetes/", "server endpoint for api calls.")

	flag.StringVar(&s.Listen, "listen", "http://0.0.0.0:8080", "")

	flag.StringVar(&s.CAFile, "ca-file", "ca.crt", "PEM File containing trusted certificates for k8s API server. If not present, the system's Root CAs will be used.")
	flag.BoolVar(&s.SkipVerifyTLS, "skip-verify-tls", false, "When true, skip verification of certs presented by k8s API server.")

	flag.StringVar(&s.CertFile, "cert-file", "cert.pem", "PEM File containing certificates.")
	flag.StringVar(&s.KeyFile, "key-file", "key.pem", "PEM File containing certificate key.")

	flag.StringVar(&s.BaseAddress, "base-address", "http://localhost:8080", "This server base address.")
	flag.StringVar(&s.ClientID, "client-id", "ocproxy-client", "OAuth2 client ID defined in a OAuthClient k8s object.")
	flag.StringVar(&s.ClientSecret, "client-secret", "my-secret", "OAuth2 client secret defined in a OAuthClient k8s object.")

	flag.Parse()

	// Print usage message
	if help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Vlidate user input
	u, err := url.Parse(s.Listen)
	if err != nil {
		panic(err)
	}

	// Register auth endpoints
	http.HandleFunc(authLoginEndpoint, login)
	http.HandleFunc(authLoginCallbackEndpoint, callback)
	http.HandleFunc(errorEndpoint, authError)

	// Register proxy service
	http.Handle(s.APIPath, middleware(proxyServer()))

	// Register static file server
	fs := http.FileServer(http.Dir(s.PublicDir))
	http.Handle(s.BasePath, middleware(fs))

	// Start proxy server
	log.Printf("Listening on %s:%s\n", u.Scheme, u.Host)
	switch u.Scheme {
	case "http":
		err = http.ListenAndServe(u.Host, nil)
	case "https":
		err = http.ListenAndServeTLS(u.Host, s.CertFile, s.KeyFile, nil)
	default:
		panic("Unknown url schema")
	}

	if err != nil {
		panic(err)
	}
}
