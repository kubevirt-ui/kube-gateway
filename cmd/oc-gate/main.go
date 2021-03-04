package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/oauth2"

	"github.com/yaacov/oc-gate/pkg/proxy"
)

const (
	authLoginEndpoint         = "/auth/login"
	authLoginCallbackEndpoint = "/auth/callback"
	authTokenEndpoint         = "/auth/token"
)

func main() {
	help := flag.Bool("help", false, "print usage.")

	publicDir := flag.String("public-dir", "./web/public", "directory containing static web assets.")
	basePath := flag.String("base-path", "/", "server endpoint for static web assets.")
	apiServer := flag.String("api-server", "", "backend API server URL.")
	apiPath := flag.String("api-path", "/k8s/", "server endpoint for API calls.")

	listen := flag.String("listen", "https://0.0.0.0:8080", "")
	baseAddress := flag.String("base-address", "https://localhost:8080", "This server base address.")

	caFile := flag.String("ca-file", "", "PEM File containing trusted certificates for k8s API server. If not present, the system's Root CAs will be used.")
	skipVerifyTLS := flag.Bool("skip-verify-tls", false, "When true, skip verification of certs presented by k8s API server.")

	certFile := flag.String("cert-file", "test/cert.pem", "PEM File containing certificates.")
	keyFile := flag.String("key-file", "test/key.pem", "PEM File containing certificate key.")

	oauthServerDisable := flag.Bool("oauth-server-disable", false, "If true will disable interactive authentication using OAuth2 issuer.")
	oauthServerTokenURL := flag.String("oauth-server-token-url", "", "OAuth2 issuer token endpoint URL.")
	oauthServerAuthURL := flag.String("oauth-server-auth-url", "", "OAuth2 issuer authentication endpoint URL.")
	oauthClientID := flag.String("oauth-client-id", "ocgate-client", "OAuth2 client ID defined in a OAuthClient k8s object.")
	oauthClientSecret := flag.String("oauth-client-secret", "my-secret", "OAuth2 client secret defined in a OAuthClient k8s object.")

	jwtTokenKeyFile := flag.String("jwt-token-key-file", "", "validate JWT token received from OAuth2 using the key in this file.")
	jwtTokenKeyAlg := flag.String("jwt-token-key-alg", "RS265", "JWT token key signing algorithm (supported algorithms HS265, RS265).")
	k8sBearerTokenfile := flag.String("k8s-bearer-token-file", "", "Replace valid JWT tokens with this token for k8s API calls.")
	k8sBearerTokenPassthrough := flag.String("k8s-bearer-token-passthrough", "false", "If \"true\" use token received from OAuth2 server as the token for k8s API calls.")

	flag.Parse()

	// Print usage message
	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Check for API server address
	if *apiServer == "" {
		log.Println("missing API server address")

		fmt.Println("Usage of oc-gate:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Read the k8s service account token from a file
	k8sBearerToken, err := ReadSABearerToken(*k8sBearerTokenfile)
	if err != nil {
		log.Fatal(err)
	}

	// Parse pass through string into boolean,
	// Note: making boolean input a string helps automation,
	// it's easier to automate "true"/"false" then "-k8s-bearer-token-passthrough"/""
	if *k8sBearerTokenPassthrough != "false" || k8sBearerToken == "" {
		log.Print("pass through bearer token from oauth issuer to k8s API calls")
	} else {
		log.Print("use user defined bearer token for k8s API calls")
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

	// Read JWT secret file
	jwtTokenKey, jwtTokenRSAKey := ReadJWTKey(*jwtTokenKeyFile, *jwtTokenKeyAlg)
	log.Printf("read JWT key file [%s]", *jwtTokenKeyFile)

	// Get auth endpoint from authentication server
	endpoint, err := GetOAuthServerEndpoints(
		oauthServerAuthURL,
		oauthServerTokenURL,
		apiServer,
		*oauthServerDisable,
		transport)
	if err != nil {
		log.Fatal(err)
	}

	// Set oauth config
	redirectURL := fmt.Sprintf("%s%s", *baseAddress, authLoginCallbackEndpoint)
	oauthConf := &oauth2.Config{
		ClientID:     *oauthClientID,
		ClientSecret: *oauthClientSecret,
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

		BearerToken:            k8sBearerToken,
		BearerTokenPassthrough: *k8sBearerTokenPassthrough != "false",
		JWTTokenKey:            jwtTokenKey,
		JWTTokenRSAKey:         jwtTokenRSAKey,

		InteractiveAuth: !*oauthServerDisable,
	}

	// Register auth endpoints
	if !*oauthServerDisable {
		http.HandleFunc(authLoginEndpoint, s.Login)
		http.HandleFunc(authLoginCallbackEndpoint, s.Callback)
	}
	http.HandleFunc(authTokenEndpoint, s.Token)

	// Register proxy service
	http.Handle(s.APIPath, s.AuthMiddleware(s.APIProxy()))

	// Register static file server
	fs := http.FileServer(http.Dir(*publicDir))
	http.Handle(*basePath, s.AuthMiddleware(fs))

	// Parse listen address
	u, err := url.Parse(*listen)
	if err != nil {
		log.Fatal(err)
	}

	// Log back end endpoints
	log.Print("-------------------------------------")
	log.Printf("k8s API server: %s", *apiServer)
	log.Printf("OAuth Token   : %s", endpoint.Token)
	log.Printf("OAuth Auth    : %s", endpoint.Auth)
	log.Printf("OAuth Issuer  : %s", endpoint.Issuer)

	// Start proxy server
	log.Print("-------------------------------------")
	log.Printf("starting server %s\n", *baseAddress)
	log.Printf("listening on [%s] %s :%s\n", u.Scheme, u.Hostname(), u.Port())
	log.Printf("Cert file: [%s] Key file: [%s]\n", *certFile, *keyFile)
	log.Print("-------------------------------------")

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
