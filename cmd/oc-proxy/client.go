package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Endpoint holds the API server authorization URL.
type Endpoint struct {
	Issuer string `json:"issuer"`
	Auth   string `json:"authorization_endpoint"`
	Token  string `json:"token_endpoint"`
}

// getServerEndpoint gets the API server well known oauth authorization endpoints.
func getServerEndpoint(serverURL string, transport *http.Transport) (Endpoint, error) {
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

// ClientTransport reads the CAFile and return init the http.Transport for the oauth2 server.
func ClientTransport(CAFile string, skipVerifyTLS bool) (*http.Transport, error) {
	var transport *http.Transport

	// Add or skip TLS
	if skipVerifyTLS {
		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 30 * time.Second,
		}
	} else if CAFile != "" {
		k8sCertPEM, err := ioutil.ReadFile(CAFile)
		if err != nil {
			return nil, err
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(k8sCertPEM) {
			err := fmt.Errorf("no CA found for the API server in file %s", CAFile)
			return nil, err
		}
		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: rootCAs},
			TLSHandshakeTimeout: 30 * time.Second,
		}
	} else {
		transport = &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		}
	}

	return transport, nil
}

// GetOAuthServerEndpoints gets authentication server endpoints
func GetOAuthServerEndpoints(oauthServerAuthURL *string, oauthServerTokenURL *string, apiServer *string, disable bool, transport *http.Transport) (Endpoint, error) {
	var endpoint Endpoint
	var err error

	if disable {
		log.Print("interactive oauth server option is disabled")
		return endpoint, nil
	}

	if *oauthServerAuthURL != "" && *oauthServerTokenURL != "" {
		endpoint.Token = *oauthServerTokenURL
		endpoint.Auth = *oauthServerAuthURL

		// Parse Issuer hostname from the token endpoint
		endpointURL, err := url.Parse(*oauthServerTokenURL)
		if err != nil {
			return endpoint, err
		}
		endpoint.Issuer = endpointURL.Host

		log.Print("using user defined oauth server endpoints")
	} else {
		endpoint, err = getServerEndpoint(*apiServer, transport)
		if err != nil {
			return endpoint, err
		}
		log.Printf("resived well known oauth server endpoints from [%s]", *apiServer)
	}

	return endpoint, nil
}
