package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	jwt "github.com/dgrijalva/jwt-go/v4"
)

func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"error\": \"%s\"}", err)
}

func validateRequest(httpMethod string, httpPath string, allowedAPIMethods string, k8sAllowedAPIRegexp *regexp.Regexp) error {
	// Validate method
	if allowedAPIMethods != "" {
		if !strings.Contains(allowedAPIMethods, strings.ToLower(httpMethod)) {
			return fmt.Errorf("%s method not allowedd", httpMethod)
		}
	}

	// Validate path
	if !k8sAllowedAPIRegexp.MatchString(httpPath) && httpPath != "/.well-known/oauth-authorization-server" {
		return fmt.Errorf("%s path not allowed", httpPath)
	}

	return nil
}

func validateToken(token string, secret string, httpMethod string, httpPath string) (*jwt.Token, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT parser error: [%s]", err)
	}

	if claims, ok := tok.Claims.(jwt.MapClaims); ok && tok.Valid {
		allowedAPIMethods := claims["allowedAPIMethods"].(string)
		allowedAPIRegexp := claims["allowedAPIRegexp"].(string)
		k8sAllowedAPIRegexp := regexp.MustCompile(allowedAPIRegexp)

		err := validateRequest(httpMethod, httpPath, allowedAPIMethods, k8sAllowedAPIRegexp)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("bearer token validation")
	}

	return tok, nil
}
