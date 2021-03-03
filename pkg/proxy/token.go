package proxy

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"kind\": \"Status\", \"api\": \"ocProxy\", \"status\": \"Forbidden\", \"message\": \"%s\",\"code\": %d}", err, http.StatusForbidden)
}

func validateRequest(httpMethod string, httpPath string, apiPAth string, allowedAPIMethods string, k8sAllowedAPIRegexp *regexp.Regexp) error {
	// Validate method
	if allowedAPIMethods != "" {
		if !strings.Contains(allowedAPIMethods, strings.ToLower(httpMethod)) {
			return fmt.Errorf("%s method not allowedd", httpMethod)
		}
	}

	// If path is API path and is not the ".well-known" endpoint
	// validate the requested regexp
	if len(httpPath) > len(apiPAth) &&
		httpPath[:len(apiPAth)] == apiPAth &&
		httpPath[len(apiPAth):] != ".well-known/oauth-authorization-server" &&
		!k8sAllowedAPIRegexp.MatchString(httpPath) {
		return fmt.Errorf("%s path not allowed", httpPath)
	}

	return nil
}

func validateToken(token string, secret []byte, publicKey *rsa.PublicKey, apiPath string, httpMethod string, httpPath string) (*jwt.Token, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); ok {
			return secret, nil
		}

		if _, ok := t.Method.(*jwt.SigningMethodRSA); ok {
			return publicKey, nil
		}

		return nil, fmt.Errorf("failed to parse token signing")
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
		var allowedAPIMethods string
		var allowedAPIRegexp string

		if allowedAPIMethods, ok = claims["allowedAPIMethods"].(string); !ok {
			allowedAPIMethods = ""
		}
		if allowedAPIRegexp, ok = claims["allowedAPIRegexp"].(string); !ok {
			allowedAPIRegexp = ""
		}
		k8sAllowedAPIRegexp := regexp.MustCompile(allowedAPIRegexp)

		err := validateRequest(httpMethod, httpPath, apiPath, allowedAPIMethods, k8sAllowedAPIRegexp)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid bearer token")
	}

	return tok, nil
}
