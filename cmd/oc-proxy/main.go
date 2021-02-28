package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"cmd/ocproxy/pkg/proxy"

	"golang.org/x/oauth2"
)

const (
	authLoginEndpoint         = "/auth/login"
	authLoginCallbackEndpoint = "/auth/callback"
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
	oauthClientID := flag.String("oauth-client-id", "ocproxy-client", "OAuth2 client ID defined in a OAuthClient k8s object.")
	oauthClientSecret := flag.String("oauth-client-secret", "my-secret", "OAuth2 client secret defined in a OAuthClient k8s object.")

	jwtTokenKeyFile := flag.String("jwt-token-key-file", "", "validate JWT token recived from OAuth2 using the key in this file.")
	k8sBearerToken := flag.String("k8s-bearer-token", "", "Replace valid JWT tokens with this token for k8s API calls.")
	k8sBearerTokenPassthrough := flag.Bool("k8s-bearer-token-passthrough", false, "If true use token recived from OAuth2 server as the token for k8s API calls.")
	k8sAllowedAPIMethodsCommaSepList := flag.String("k8s-allowed-methods", "get,options", "Comma seperated list of allowed HTTP methods for k8s API calls.")
	k8sAllowedAPIRegexpStr := flag.String("k8s-allowed-regexp", "", "If exist only API calls matching this regexp will be allowed.")

	flag.Parse()

	// Print usage message
	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Parse allowed http methods
	log.Printf("allowed HTTP methods for k8s API calls: %s", *k8sAllowedAPIMethodsCommaSepList)

	// Compile allowed API regexp
	k8sAllowedAPIRegexp := regexp.MustCompile(*k8sAllowedAPIRegexpStr)
	if *k8sAllowedAPIRegexpStr == "" {
		log.Print("allow any path for k8s API calls")
	} else {
		log.Printf("allowed rexexp for k8s API calls: %s", *k8sAllowedAPIRegexpStr)
	}

	if *k8sBearerTokenPassthrough || *k8sBearerToken == "" {
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
	var jwtTokenKey []byte
	if *jwtTokenKeyFile != "" {
		jwtTokenKey, err = ioutil.ReadFile(*jwtTokenKeyFile)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("read JWT (HS256-secret or rsa-public-key file) [%s]", *jwtTokenKeyFile)

	// Get auth endpoint from authentication server
	endpoint, err := GetEndpoints(oauthServerAuthURL, oauthServerTokenURL, apiServer, *oauthServerDisable, transport)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("endpoints: %+v", endpoint)

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

		AllowedAPIMethods: *k8sAllowedAPIMethodsCommaSepList,
		AllowedAPIRegexp:  k8sAllowedAPIRegexp,

		BearerToken:            *k8sBearerToken,
		BearerTokenPassthrough: *k8sBearerTokenPassthrough,
		JWTTokenKey:            jwtTokenKey,

		OAuthServerDisable: *oauthServerDisable,
	}

	// Register auth endpoints
	if !*oauthServerDisable {
		http.HandleFunc(authLoginEndpoint, s.Login)
		http.HandleFunc(authLoginCallbackEndpoint, s.Callback)
	}

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
		log.Printf("Cert file: [%s] Key file: [%s]\n", *certFile, *keyFile)
		err = http.ListenAndServeTLS(u.Host, *certFile, *keyFile, nil)
	default:
		err = fmt.Errorf("Unknown url schema %s", u.Scheme)
	}

	if err != nil {
		log.Fatal(err)
	}
}
