package main

import (
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang/glog"

	"github.com/kubevirt-ui/kube-gateway/pkg/oauth"
	"github.com/kubevirt-ui/kube-gateway/pkg/proxy"
	"github.com/kubevirt-ui/kube-gateway/pkg/token"
)

const (
	authLoginEndpoint         = "/auth/login"
	authLogoutEndpoint        = "/auth/logout"
	authLoginCallbackEndpoint = "/auth/callback"
	requestTokenEndpoint      = "/auth/jwt/request"
	setTokenEndpoint          = "/auth/jwt/set"
)

func main() {
	var err error
	var k8sBearerToken string
	var jwtTokenRSAKey *rsa.PublicKey
	var transport *http.Transport
	var oauthServer *oauth.OAuth

	help := flag.Bool("help", false, "print usage.")

	publicDir := flag.String("public-dir", "./web/public", "localhost directory containing static web assets.")
	basePath := flag.String("base-path", "/", "url endpoint for static web assets.")
	apiPath := flag.String("api-path", "/k8s/", "url endpoint for API calls.")

	apiServer := flag.String("api-server", "https://kubernetes.default.svc", "backend API server URL.")
	apiServerSkipVerifyTLS := flag.Bool("api-server-skip-verify-tls", false, "When true, skip verification of certs presented by k8s API server.")
	apiServerCAFile := flag.String("api-server-ca-file", "ca.crt", "PEM File containing trusted certificates for k8s API server. If not present, the system's Root CAs will be used.")
	apiServerBearerTokenfile := flag.String("api-server-bearer-token-file", "token", "service account bearer token filename, the proxy will use this service account to execute requests validated by JWT.")

	gatewayListen := flag.String("gateway-listen", "https://0.0.0.0:8080", "This server will listen on.")
	gatewayCertFile := flag.String("gateway-cert-file", "tls.crt", "PEM File containing certificates (when listen adress use TLS, e.g. https://).")
	gatewayKeyFile := flag.String("gateway-key-file", "tls.key", "PEM File containing certificate key (when listen adress use TLS, e.g. https://).")

	oauthServerEnable := flag.Bool("oauth-server-enable", false, "enable interactive OAuth2 issuer.")
	oauthServerCallbackAddress := flag.String("oauth-server-callback-address", "https://localhost:8080", "OAuth2 client callback host.")
	oauthServerTokenURL := flag.String("oauth-server-token-url", "", "OAuth2 issuer token endpoint URL.")
	oauthServerAuthURL := flag.String("oauth-server-auth-url", "", "OAuth2 issuer authentication endpoint URL.")
	oauthServerClientID := flag.String("oauth-server-client-id", "", "OAuth2 client ID defined in a OAuthClient k8s object.")
	oauthServerClientSecret := flag.String("oauth-server-client-secret", "", "OAuth2 client secret defined in a OAuthClient k8s object.")

	JWTRequestEnable := flag.Bool("jwt-request-enable", false, "enable optional request for signed JWT endpoint (requires k8s bearer token with access to JWT secret).")
	JWTPublicKeyName := flag.String("jwt-public-key-name", "kube-gateway-jwt", "JWT secret is used to sign and verify the gateway JWT, name of the public key secret.")
	JWTPublicKeyNamespace := flag.String("jwt-public-key-namespace", "kube-gateway", "JWT secret is used to sign and verify the gateway JWT, namespace of the public key secret.")
	JWTPuplicKeyFileName := flag.String("jwt-public-key-filename", "tls.crt", "JWT secret is used to sign and verify the gateway JWT, public key item in secret")
	JWTPrivateKeyName := flag.String("jwt-private-key-name", "kube-gateway-jwt", "JWT secret is used to sign and verify the gateway JWT, name of the private key secret.")
	JWTPrivateKeyNamespace := flag.String("jwt-private-key-namespace", "kube-gateway", "JWT secret is used to sign and verify the gateway JWT, namespace of the private key secret.")
	JWTPrivateKeyFileName := flag.String("jwt-private-key-filename", "tls.key", "JWT secret is used to sign and verify the gateway JWT, private key item in secret.")

	flag.Set("logtostderr", "true")
	flag.Parse()

	// Print usage message
	if *help {
		PrintHelpMsg()
	}

	// Check for API server address
	if *apiServer == "" {
		LogErrorAndExit(errors.New("missing API server address"))
	}

	// Read CAFile, add or skip TLS to transport
	transport = GetTLSTranport(apiServerSkipVerifyTLS, apiServerCAFile)

	glog.Info("-------------------------------------")
	glog.Infof("k8s API server: [%s]", *apiServer)

	// Get k8s service account Bearer token, used to execute requests verified using signed JWT
	glog.Info("-------------------------------------")
	if *apiServerBearerTokenfile != "" {
		glog.Infof("get k8s service account Bearer token from file [%s]", *apiServerBearerTokenfile)
		k8sBearerToken = GetK8sBearerToken(apiServerBearerTokenfile)
	} else {
		glog.Info("[WARN] fail to get k8s service account Bearer token, will not be able to access k8s resources using internal SA")
	}

	// Get JWT public key secret, we will use this file to verify authentication of signed JWT
	// Requires access to cluster secrets
	glog.Info("-------------------------------------")
	if *apiServerBearerTokenfile != "" {
		glog.Infof("get JWT public key from secret [%s/%s:%s]", *JWTPublicKeyNamespace, *JWTPublicKeyName, *JWTPuplicKeyFileName)

		jwtTokenRSAKey, err = GetJWTPuplicKey(k8sBearerToken, transport, *apiServer, *JWTPublicKeyNamespace, *JWTPublicKeyName, *JWTPuplicKeyFileName)
		if err != nil {
			glog.Infof("[ERROR] fail to get JWT public key from secret, will not be able to access k8s resources using JWT, %+v", err)
		}
	} else {
		glog.Info("[WARN] fail to get JWT public key from secret, will not be able to access k8s resources using JWT")
	}

	// Optionsal:
	// Set request JWT endpoints
	// http(s)://<gateway url>/token/request - request signed JWT tokens from the server
	if *JWTRequestEnable {
		glog.Info("-------------------------------------")
		glog.Info("JWT request support enabled")
		glog.Infof("private key from secret [%s/%s:%s]", *JWTPrivateKeyNamespace, *JWTPrivateKeyName, *JWTPrivateKeyFileName)

		// Add set token cookie endpoint
		t := token.Token{
			APIServerURL: *apiServer,
			APITransport: transport,

			JWTSecretName:         *JWTPrivateKeyName,
			JWTSecretNamespace:    *JWTPrivateKeyNamespace,
			JWTPrivateKeyFileName: *JWTPrivateKeyFileName,
		}

		// Register token request endpoints
		http.HandleFunc(requestTokenEndpoint, t.GetToken)
	} else {
		glog.Info("-------------------------------------")
		glog.Info("JWT request support disabled")
	}

	// Optionsal:
	// Set oauth2 endpoints
	// http(s)://<gateway url>/auth/login - redirect to oauth server login page
	// http(s)://<gateway url>/auth/logout - redirect to oauth server logout page (if exist)
	// http(s)://<gateway url>/auth/callback - callback page for the oauth server to callback
	if *oauthServerEnable {
		glog.Info("-------------------------------------")
		glog.Info("OAuth2 support enabled")

		// Init server
		oauthConf := GetOAuthConf(oauthServerAuthURL, oauthServerTokenURL, apiServer,
			oauthServerCallbackAddress, oauthServerClientID, oauthServerClientSecret, transport)
		oauthServer = &oauth.OAuth{
			APITransport: transport,
			Auth2Config:  oauthConf,
		}

		// Register oauth2 endpoints
		http.HandleFunc(authLoginEndpoint, oauthServer.Login)
		http.HandleFunc(authLogoutEndpoint, oauthServer.Logout)
		http.HandleFunc(authLoginCallbackEndpoint, oauthServer.Callback)
	} else {
		glog.Info("-------------------------------------")
		glog.Info("OAuth2 support disabled")
	}

	// Register the k8s proxy endpoints
	s := &proxy.Server{
		APIPath:     *apiPath,
		BaseAddress: *basePath,

		APIServerURL: *apiServer,
		APITransport: transport,
		BearerToken:  k8sBearerToken,

		JWTTokenRSAKey: jwtTokenRSAKey,

		OAuthServer: oauthServer,
	}
	http.Handle(s.APIPath, s.AuthMiddleware(s.APIProxy()))

	// Register set token cookie endpoint
	http.HandleFunc(setTokenEndpoint, token.SetToken)

	// Register static file server
	fs := http.FileServer(http.Dir(*publicDir))
	http.Handle(*basePath, s.AuthMiddleware(fs))

	// Start proxy server
	u, err := url.Parse(*gatewayListen)
	if err != nil {
		LogErrorAndExit(err)
	}

	glog.Info("-------------------------------------")
	if u.Scheme == "https" {
		glog.Infof("public key file : [%s]", *gatewayCertFile)
		glog.Infof("private key file: [%s]", *gatewayKeyFile)
	}
	glog.Infof("listening on    : [%s]", *gatewayListen)

	glog.Flush()

	switch u.Scheme {
	case "http":
		err = http.ListenAndServe(u.Host, nil)
	case "https":
		err = http.ListenAndServeTLS(u.Host, *gatewayCertFile, *gatewayKeyFile, nil)
	default:
		err = fmt.Errorf("unknown url schema [%s]", u.Scheme)
	}

	if err != nil {
		LogErrorAndExit(err)
	}
}
