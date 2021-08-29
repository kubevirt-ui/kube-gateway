package proxy

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/golang/glog"
)

func handleError(w http.ResponseWriter, err error) {
	msg := map[string]interface{}{
		"kind":    "Status",
		"api":     "ocgate",
		"status":  "Forbidden",
		"message": err.Error(),
		"code":    http.StatusForbidden,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(msg)
}

func validateRequest(httpMethod string, httpPath string, apiPAth string, verbs map[string]bool, patterns []string) error {
	// validate method
	if len(verbs) == 0 || len(patterns) == 0 {
		return fmt.Errorf("missing validation verbs or patterns")
	}

	// check for matching verb
	if _, ok := verbs[strings.ToLower(httpMethod)]; !ok {
		return fmt.Errorf("%s method not allowedd", httpMethod)
	}

	// check for matching pattern
	matchURL := false
	for _, pattern := range patterns {
		glog.V(2).Infof("matching: %s ? %s", httpPath, pattern)

		if pattern[(len(pattern)-1):] == "*" {
			// check for pattern matching prefix of path
			if strings.HasPrefix(httpPath, pattern[:(len(pattern)-1)]) {
				matchURL = true
				break
			}
		} else {
			// check for pattern matching the path
			if pattern == httpPath {
				matchURL = true
				break
			}
		}
	}

	if !matchURL {
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
		verbs, _ := claims["verbs"].([]interface{})
		urls, _ := claims["URLs"].([]interface{})

		glog.Infof("JWT ID: %+v", claims["id"])

		glog.V(2).Infof("JWT claims: %+v", claims)
		glog.V(2).Infof("JWT verbs: %+v", verbs)
		glog.V(2).Infof("JWT patterns: %+v", urls)

		verbsMap := make(map[string]bool)
		for _, verb := range verbs {
			verbsMap[strings.ToLower(verb.(string))] = true
		}

		patterns := make([]string, len(urls))
		for i, pattern := range urls {
			patterns[i] = pattern.(string)
		}

		err := validateRequest(httpMethod, httpPath, apiPath, verbsMap, patterns)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid bearer token")
	}

	return tok, nil
}
