package proxy

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
)

func handleError(w http.ResponseWriter, err error) {
	msg := map[string]interface{}{
		"kind":    "Status",
		"api":     "ocgate",
		"status":  "Forbidden",
		"message": err.Error(),
		"code":    http.StatusBadRequest,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

func validateRequest(httpMethod string, httpPath string, apiPAth string, verbs map[string]bool, URL string) error {
	urlCheck := URL
	httpPathCheck := httpPath

	// Validate method
	if len(verbs) != 0 {
		if _, ok := verbs[strings.ToLower(httpMethod)]; !ok {
			return fmt.Errorf("%s method not allowedd", httpMethod)
		}
	}

	// CHeck for '*' postfix of token URL
	if URL[(len(URL)-1):] == "*" {
		urlCheck = URL[:(len(URL) - 1)]

		if len(urlCheck) > len(httpPath) {
			return fmt.Errorf("%s path not allowed (length)", httpPath)
		}
		httpPathCheck = httpPath[:len(urlCheck)]
	}

	// If path is API path and is not the ".well-known" endpoint
	// validate the requested regexp
	if httpPathCheck != urlCheck {
		return fmt.Errorf("%s path not allowed", httpPath)
	}

	return nil
}

func validateToken(token string, publicKey *rsa.PublicKey, apiPath string, httpMethod string, httpPath string) (*jwt.Token, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); ok {
			return publicKey, nil
		}

		return nil, fmt.Errorf("failed to parse token signing")
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
		verbs, _ := claims["Verbs"].([]string)
		url, _ := claims["URL"].(string)

		verbsMap := make(map[string]bool)
		for i := 0; i < len(verbs); i += 2 {
			verbsMap[strings.ToLower(verbs[i])] = true
		}

		err := validateRequest(httpMethod, httpPath, apiPath, verbsMap, url)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid bearer token")
	}

	return tok, nil
}
