package main

import (
	"crypto/rsa"
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
	corev1 "k8s.io/api/core/v1"
)

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
