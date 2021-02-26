package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// Endpoint holds the API server authorization URL.
type Endpoint struct {
	Issuer string `json:"issuer"`
	Auth   string `json:"authorization_endpoint"`
	Token  string `json:"token_endpoint"`
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

// ServerEndpoint gets the API server well known oauth authorization endpoints.
func ServerEndpoint(serverURL string, transport *http.Transport) (Endpoint, error) {
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
