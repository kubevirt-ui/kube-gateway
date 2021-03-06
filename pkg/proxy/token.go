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
	fmt.Fprintf(w, "{\"kind\": \"Status\", \"api\": \"ocgate\", \"status\": \"Forbidden\", \"message\": \"%s\",\"code\": %d}", err, http.StatusForbidden)
}

func validateRequest(httpMethod string, httpPath string, apiPAth string, matchMethod string, matchPathRegexp *regexp.Regexp) error {
	// Validate method
	if matchMethod != "" {
		if !strings.Contains(strings.ToLower(matchMethod), strings.ToLower(httpMethod)) {
			return fmt.Errorf("%s method not allowedd", httpMethod)
		}
	}

	// If path is API path and is not the ".well-known" endpoint
	// validate the requested regexp
	if len(httpPath) > len(apiPAth) &&
		httpPath[:len(apiPAth)] == apiPAth &&
		httpPath[len(apiPAth):] != "/.well-known/oauth-authorization-server" &&
		!matchPathRegexp.MatchString(httpPath) {
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
		var matchMethod string
		var matchPath string

		if matchMethod, ok = claims["matchMethod"].(string); !ok {
			matchMethod = ""
		}
		if matchPath, ok = claims["matchPath"].(string); !ok {
			matchPath = ""
		}
		matchPathRegexp := regexp.MustCompile(matchPath)

		err := validateRequest(httpMethod, httpPath, apiPath, matchMethod, matchPathRegexp)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid bearer token")
	}

	return tok, nil
}
