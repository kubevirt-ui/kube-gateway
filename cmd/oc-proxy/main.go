package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"cmd/ocproxy/pkg/proxy"

	"golang.org/x/oauth2"
)

const (
	authLoginEndpoint         = "/auth/login"
	authLogoutEndpoint        = "/auth/logout"
	authLoginCallbackEndpoint = "/auth/callback"
)

func main() {
	help := flag.Bool("help", false, "print usage.")

	publicDir := flag.String("public-dir", "./web/public", "directory containing static web assets.")
	basePath := flag.String("base-path", "/", "server endpoint for static web assets.")
	apiServer := flag.String("api-server", "", "backend API server URL.")
	apiPath := flag.String("api-path", "/k8s/", "server endpoint for API calls.")
	listen := flag.String("listen", "https://0.0.0.0:8080", "")
	caFile := flag.String("ca-file", "", "PEM File containing trusted certificates for k8s API server. If not present, the system's Root CAs will be used.")
	skipVerifyTLS := flag.Bool("skip-verify-tls", false, "When true, skip verification of certs presented by k8s API server.")
	certFile := flag.String("cert-file", "cert.pem", "PEM File containing certificates.")
	keyFile := flag.String("key-file", "key.pem", "PEM File containing certificate key.")
	baseAddress := flag.String("base-address", "https://localhost:8080", "This server base address.")
	clientID := flag.String("client-id", "ocproxy-client", "OAuth2 client ID defined in a OAuthClient k8s object.")
	clientSecret := flag.String("client-secret", "my-secret", "OAuth2 client secret defined in a OAuthClient k8s object.")

	flag.Parse()

	// Print usage message
	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Read CAFile
	transport, err := ClientTransport(*caFile, *skipVerifyTLS)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("skip TSL verify: %v", *skipVerifyTLS)
	if !*skipVerifyTLS {
		log.Printf("read CAFile [%s]", *caFile)
	}

	// Get auth endpoint from authentication server
	endpoint, err := ServerEndpoint(*apiServer, transport)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("resived well known auth endpoints from [%s]", *apiServer)
	log.Printf("endpoints: %+v", endpoint)

	// Set oauth config
	redirectURL := fmt.Sprintf("%s%s", *baseAddress, authLoginCallbackEndpoint)
	oauthConf := &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Scopes:       []string{"user:full"},
		Endpoint: oauth2.Endpoint{
			TokenURL: endpoint.Token,
			AuthURL:  endpoint.Auth,
		},
		RedirectURL: redirectURL,
	}

	// Init server
	s := &proxy.Server{
		APIPath:      *apiPath,
		APIServerURL: *apiServer,
		APITransport: transport,
		Auth2Config:  oauthConf,

		BaseAddress:    *baseAddress,
		IssuerEndpoint: endpoint.Issuer,
		LoginEndpoint:  authLoginEndpoint,
	}

	// Register auth endpoints
	http.HandleFunc(authLoginEndpoint, s.Login)
	http.HandleFunc(authLoginCallbackEndpoint, s.Callback)
	http.HandleFunc(authLogoutEndpoint, s.Logout)

	// Register proxy service
	http.Handle(s.APIPath, s.AuthMiddleware(s.Proxy()))

	// Register static file server
	fs := http.FileServer(http.Dir(*publicDir))
	http.Handle(*basePath, s.AuthMiddleware(fs))

	// Parse listen address
	u, err := url.Parse(*listen)
	if err != nil {
		log.Fatal(err)
	}

	// Start proxy server
	log.Printf("starting server %s\n", *baseAddress)
	log.Printf("listening on [%s] %s :%s\n", u.Scheme, u.Hostname(), u.Port())
	switch u.Scheme {
	case "http":
		err = http.ListenAndServe(u.Host, nil)
	case "https":
		err = http.ListenAndServeTLS(u.Host, *certFile, *keyFile, nil)
	default:
		err = fmt.Errorf("Unknown url schema %s", u.Scheme)
	}

	if err != nil {
		log.Fatal(err)
	}
}
