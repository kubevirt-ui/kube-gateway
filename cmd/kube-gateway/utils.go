package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/golang/glog"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
)

// Endpoint holds the API server authorization URL.
type Endpoint struct {
	Auth  string `json:"authorization_endpoint"`
	Token string `json:"token_endpoint"`
}

// PrintHelpMsg prints a help message and exit with success status
func PrintHelpMsg() {
	flag.PrintDefaults()
	os.Exit(0)
}

// LogErrorAndExit prints a error message and exit with error status
func LogErrorAndExit(err error) {
	glog.Error(err)
	os.Exit(1)
}

// GetK8sBearerToken read k8s bearer token string from a file
func GetK8sBearerToken(k8sBearerTokenfile *string) string {
	var k8sBearerToken string

	k8sBearerTokenBytes, err := ioutil.ReadFile(*k8sBearerTokenfile)
	if err != nil {
		LogErrorAndExit(err)
	}
	k8sBearerToken = string(k8sBearerTokenBytes)
	k8sBearerToken = strings.TrimSpace(k8sBearerToken)

	return k8sBearerToken
}

// GetJWTPuplicKey gets the puglic key secret from k8s API server.
func GetJWTPuplicKey(bearer string, APITransport http.RoundTripper, APIServerURL string, namespace string, JWTSecretName string, JWTPuplicKeyFileName string) (*rsa.PublicKey, error) {
	var secret *corev1.Secret
	var jwtTokenRSAKey *rsa.PublicKey
	client := &http.Client{Transport: APITransport, Timeout: 30 * time.Second}

	secretURL := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", APIServerURL, namespace, JWTSecretName)
	req, err := http.NewRequest("GET", secretURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearer))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fail to get secret, error: %+v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fail to get secret, http status: %v", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, fmt.Errorf("fail to parse secret: %+v", err)
	}

	publicKey := secret.Data[JWTPuplicKeyFileName]
	jwtTokenRSAKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKey)

	return jwtTokenRSAKey, err
}

// GetOAuthConf gets the oauth2 config object
func GetOAuthConf(oauthServerAuthURL *string, oauthServerTokenURL *string, apiServer *string, gatewayBaseAddress *string, oauthServerClientID *string, oauthServerClientSecret *string, transport *http.Transport) *oauth2.Config {
	var endpoint Endpoint
	var oauthConf *oauth2.Config
	var err error

	// Try to autodetect auth sever endpoints
	if *oauthServerAuthURL != "" && *oauthServerTokenURL != "" {
		endpoint.Token = *oauthServerTokenURL
		endpoint.Auth = *oauthServerAuthURL
	} else {
		endpoint, err = GetServerEndpoint(*apiServer, transport)
		if err != nil {
			LogErrorAndExit(err)
		}
		glog.Infof("auto detect oauth server endpoints from [%s]", *apiServer)
	}

	// Set oauth config
	redirectURL := fmt.Sprintf("%s%s", *gatewayBaseAddress, authLoginCallbackEndpoint)
	oauthConf = &oauth2.Config{
		ClientID:     *oauthServerClientID,
		ClientSecret: *oauthServerClientSecret,
		Scopes:       []string{"user:full"},
		Endpoint: oauth2.Endpoint{
			TokenURL: endpoint.Token,
			AuthURL:  endpoint.Auth,
		},
		RedirectURL: redirectURL,
	}

	glog.Infof("OAuth Token : [%s]", endpoint.Token)
	glog.Infof("OAuth Auth  : [%s]", endpoint.Auth)

	return oauthConf
}

// GetTLSTranport creats a http transport for comunication with k8s cluster
func GetTLSTranport(skipVerifyTLS *bool, apiServerCAFile *string) *http.Transport {
	var transport *http.Transport

	if *skipVerifyTLS {
		glog.Info("skip TSL verify when connecting to k8s server")

		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 30 * time.Second,
		}
	} else if *apiServerCAFile != "" {
		glog.Infof("use CA File [%s] file when connecting to k8s server", *apiServerCAFile)

		k8sCertPEM, err := ioutil.ReadFile(*apiServerCAFile)
		if err != nil {
			LogErrorAndExit(err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(k8sCertPEM) {
			LogErrorAndExit(fmt.Errorf("no CA found for the API server in file %s", *apiServerCAFile))
		}
		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: rootCAs},
			TLSHandshakeTimeout: 30 * time.Second,
		}
	} else {
		glog.Info("use system's Root CAs when connecting to k8s server (use -ca-file to specify a specifc certification file or -skip-verify-tls for insecure connection)")

		transport = &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		}
	}

	return transport
}

// GetServerEndpoint gets the API server well known oauth authorization endpoints.
func GetServerEndpoint(serverURL string, transport *http.Transport) (Endpoint, error) {
	var endpoint Endpoint
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	wellKnownURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", serverURL)
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return endpoint, fmt.Errorf("fail to get well-known oauth-authorization-server: %+v", err)
	}

	if err := json.NewDecoder(resp.Body).Decode(&endpoint); err != nil {
		return endpoint, fmt.Errorf("fail to get well known authorization endpoints: %+v", err)
	}

	return endpoint, nil
}
