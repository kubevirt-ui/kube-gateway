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
	JWTSecretName         = "kube-gateway-jwt-secret"
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
func cacheData(t *ocgatev1beta1.GateToken) error {
	var notBeforeTime int64

	// Default from is "now"
	if t.Spec.From == "" {
		notBeforeTime = int64(time.Now().Unix())
	} else {
		fromTime, err := time.Parse(time.RFC3339, t.Spec.From)
		if err != nil {
			return err
		}
		notBeforeTime = int64(fromTime.Unix())
	}

	// Default Namespace is "*"
	if t.Spec.Namespace == "" {
		t.Spec.Namespace = "*"
	}

	// Default Verbs is ["get"]
	if t.Spec.Verbs == nil {
		t.Spec.Verbs = []string{"get"}
	}

	// Default DurationSec is 3600s (1h)
	if t.Spec.DurationSec == 0 {
		t.Spec.DurationSec = 3600
	}

	// Set gate token cache data
	t.Status.Data = ocgatev1beta1.GateTokenCache{
		NBf:             notBeforeTime,
		Exp:             notBeforeTime + int64(t.Spec.DurationSec),
		From:            time.Unix(notBeforeTime, 0).UTC().Format(time.RFC3339),
		Until:           time.Unix(notBeforeTime+int64(t.Spec.DurationSec), 0).UTC().Format(time.RFC3339),
		DurationSec:     t.Spec.DurationSec,
		Namespace:       t.Spec.Namespace,
		Verbs:           t.Spec.Verbs,
		APIGroups:       t.Spec.APIGroups,
		Resources:       t.Spec.Resources,
		ResourceNames:   t.Spec.ResourceNames,
		NonResourceURLs: t.Spec.NonResourceURLs,
		Alg:             jwt.SigningMethodRS256.Name,
	}

	return nil
}

func singToken(token *ocgatev1beta1.GateToken, key []byte) error {
	claims := &jwt.MapClaims{
		"exp":             token.Status.Data.Exp,
		"nbf":             token.Status.Data.NBf,
		"namespace":       token.Status.Data.Namespace,
		"verbs":           token.Status.Data.Verbs,
		"apiGroups":       token.Status.Data.APIGroups,
		"resources":       token.Status.Data.Resources,
		"resourceNames":   token.Status.Data.ResourceNames,
		"nonResourceURLs": token.Status.Data.NonResourceURLs,
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
