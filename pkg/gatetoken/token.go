package gatetoken

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	ocgatev1beta1 "github.com/yaacov/oc-gate-operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// JWTSecretName is the name of the secret holding the private and public SSH keys
// for authenticating the JWT access codes.
const (
	JWTSecretName         = "oc-gate-jwt-secret"
	JWTPrivateKeyFileName = "key.pem"
)

// getPrivateKey gets the private key secret from k8s API server.
func (s Server) getPrivateKey(namespace string, bearer string) ([]byte, error) {
	var secret *corev1.Secret
	client := &http.Client{Transport: s.APITransport, Timeout: 30 * time.Second}

	secretURL := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", s.APIServerURL, namespace, JWTSecretName)
	req, err := http.NewRequest("GET", secretURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearer))
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fail to get secret: %v %+v", resp.Status, err)
	}

	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, fmt.Errorf("fail to parse secret: %+v", err)
	}

	return secret.Data[JWTPrivateKeyFileName], nil
}

// Cache user data
func cacheData(token *ocgatev1beta1.GateToken) error {
	var nbf int64

	// Default from is "now"
	if token.Spec.From == "" {
		nbf = int64(time.Now().Unix())
	} else {
		t, err := time.Parse(time.RFC3339, token.Spec.From)
		if err != nil {
			return err
		}
		nbf = int64(t.Unix())
	}

	// Default MatchMethod is "GET,OPTIONS"
	if token.Spec.MatchMethod == "" {
		token.Spec.MatchMethod = "GET,OPTIONS"
	}

	// Default DurationSec is 3600s (1h)
	if token.Spec.DurationSec == 0 {
		token.Spec.DurationSec = 3600
	}

	// Set gate token cache data
	token.Status.Data = ocgatev1beta1.GateTokenCache{
		NBf:         nbf,
		Exp:         nbf + int64(token.Spec.DurationSec),
		From:        time.Unix(nbf, 0).UTC().Format(time.RFC3339),
		Until:       time.Unix(nbf+int64(token.Spec.DurationSec), 0).UTC().Format(time.RFC3339),
		DurationSec: token.Spec.DurationSec,
		MatchMethod: token.Spec.MatchMethod,
		MatchPath:   token.Spec.MatchPath,
		Alg:         jwt.SigningMethodRS256.Name,
	}

	return nil
}

func singToken(token *ocgatev1beta1.GateToken, key []byte) error {
	// Create token
	claims := &jwt.MapClaims{
		"exp":         token.Status.Data.Exp,
		"nbf":         token.Status.Data.NBf,
		"matchPath":   token.Status.Data.MatchPath,
		"matchMethod": token.Status.Data.MatchMethod,
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return err
	}
	out, err := jwtToken.SignedString(jwtKey)
	if err != nil {
		return err
	}

	token.Status.Token = out
	token.Status.Phase = "Ready"

	return nil
}
