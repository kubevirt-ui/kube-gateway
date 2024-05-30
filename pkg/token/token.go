package token

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
)

const (
	// CookieName is used in web browser to store the signed JWT token
	// sidned using the JWT private key.
	CookieName = "kg-jwt-session-code"
)

// Token holds information required for serving files.
type Token struct {
	APIServerURL string
	APITransport *http.Transport

	JWTSecretName         string
	JWTSecretNamespace    string
	JWTPrivateKeyFileName string
}

// GateToken holds information required for serving files.
type GateToken struct {
	ID       string
	From     string
	Verbs    []string
	Duration string
	URLs     []string
	NBf      int64
	Exp      int64
	Until    string
	Token    string
}

// HandlerFunc is a type alias for a function that handles HTTP requests.
type HandlerFunc func(w http.ResponseWriter, r *http.Request)

// Factory function that returns a SetTokenHandler
func SetTokenFactory(clientPath string, apiPath string) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log request
		glog.Infof("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

		var token string
		var name string
		var namespace string

		// Get token and redirect from get request
		if r.Method == http.MethodGet {
			query := r.URL.Query()
			token = query.Get("token")
			name = query.Get("name")
			namespace = query.Get("namespace")
		}

		// Get token and redirect from post request
		if r.Method == http.MethodPost {
			token = r.FormValue("token")
			name = r.FormValue("name")
			namespace = r.FormValue("namespace")
		}

		// Build the redirect URL
		cleanApiPath := apiPath[1:] // Remove prefix `/` from the begining of apiPath
		then := fmt.Sprintf("%s?path=%sapis/subresources.kubevirt.io/v1/namespaces/%s/virtualmachineinstances/%s/vnc", clientPath, cleanApiPath, namespace, name)

		// Set session cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    token,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			HttpOnly: true})
		http.Redirect(w, r, then, http.StatusFound)
	}
}

// GetToken handle callbacs from OAuth2 authtorization server.
func (s Token) GetToken(w http.ResponseWriter, r *http.Request) {
	// Log request
	glog.Infof("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	// Check request method, we only allow post requests.
	if r.Method != http.MethodPost {
		handleError(w, fmt.Errorf("%s is not allowed", r.Method))
		return
	}

	// Get bearer token from request
	bearer, err := GetRequestBearerToken(r)
	if err != nil {
		handleError(w, fmt.Errorf("fail to get authorization: %+v", err))
		return
	}

	// Create an empty gate token
	gateToken := &GateToken{}

	// Parse request body as gate token spec
	if err := json.NewDecoder(r.Body).Decode(&gateToken); err != nil {
		handleError(w, fmt.Errorf("fail to parse token request: %+v", err))
		return
	}

	// Cache token data in the spec section
	cacheData(gateToken)

	// Get private key secret for signing JWT
	privateKeyBytes, err := s.getPrivateKey(bearer)
	if err != nil {
		handleError(w, fmt.Errorf("secret error: %+v", err))
		return
	}

	// Sign the token
	if err := singToken(gateToken, privateKeyBytes); err != nil {
		handleError(w, fmt.Errorf("fail to sign token: %+v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gateToken)
}

// GetRequestBearerToken parses a request and get the token to pass to k8s API
func GetRequestBearerToken(r *http.Request) (string, error) {
	// Check for Authorization HTTP header
	if authorization := r.Header.Get("Authorization"); len(authorization) > 7 && authorization[:7] == "Bearer " {
		return authorization[7:], nil
	}

	return "", fmt.Errorf("faile to read authorization header")
}

// getPrivateKey gets the private key secret from k8s API server.
func (s Token) getPrivateKey(bearer string) ([]byte, error) {
	var secret *corev1.Secret
	client := &http.Client{Transport: s.APITransport, Timeout: 30 * time.Second}

	secretURL := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", s.APIServerURL, s.JWTSecretNamespace, s.JWTSecretName)
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

	return secret.Data[s.JWTPrivateKeyFileName], nil
}

// Cache user data
func cacheData(t *GateToken) error {
	var notBeforeTime int64
	var duration time.Duration

	// Default from is "now"
	if t.From == "" {
		notBeforeTime = int64(time.Now().Unix())
	} else {
		fromTime, err := time.Parse(time.RFC3339, t.From)
		if err != nil {
			return err
		}
		notBeforeTime = int64(fromTime.Unix())
	}

	// Default Verbs is ["get"]
	if t.Verbs == nil {
		t.Verbs = []string{"get"}
	}

	// Default DurationSec is 3600s (1h)
	if t.Duration == "" {
		t.Duration = "1h"
	}

	// Set gate token cache data
	duration, _ = time.ParseDuration(t.Duration)
	t.NBf = notBeforeTime
	t.Exp = notBeforeTime + int64(duration.Seconds())
	t.From = time.Unix(notBeforeTime, 0).UTC().Format(time.RFC3339)
	t.Until = time.Unix(notBeforeTime+int64(duration.Seconds()), 0).UTC().Format(time.RFC3339)

	return nil
}

func singToken(t *GateToken, key []byte) error {
	claims := &jwt.MapClaims{
		"exp":   t.Exp,
		"nbf":   t.NBf,
		"id":    t.ID,
		"verbs": t.Verbs,
		"URLs":  t.URLs,
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

	t.Token = out

	return nil
}

func handleError(w http.ResponseWriter, err error) {
	msg := map[string]interface{}{
		"kind":   "Error",
		"api":    "kube-gateway/token",
		"status": err.Error(),
		"code":   http.StatusForbidden,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(msg)
}
