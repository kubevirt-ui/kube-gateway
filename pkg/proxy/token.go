package proxy

import (
	"crypto/rsa"
	"fmt"
	"log"
	"strings"

	"github.com/dgrijalva/jwt-go"
	ocgatev1beta1 "github.com/yaacov/oc-gate-operator/api/v1beta1"
)

func authenticateToken(token string, secret []byte, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); ok {
			return secret, nil
		}

		if _, ok := t.Method.(*jwt.SigningMethodRSA); ok {
			return publicKey, nil
		}

		return nil, fmt.Errorf("failed to parse token signing")
	})

	return tok, err
}

func getTokenData(claims jwt.MapClaims) ocgatev1beta1.GateToken {
	var t ocgatev1beta1.GateToken
	var ok bool

	if t.Status.Data.Namespace, ok = claims["namespace"].(string); !ok {
		t.Status.Data.Namespace = "*"
	}

	if t.Status.Data.Verbs, ok = claims["verbs"].([]string); !ok {
		t.Status.Data.Verbs = []string{"get"}
	}

	if t.Status.Data.APIGroups, ok = claims["apiGroups"].([]string); !ok {
		t.Status.Data.APIGroups = nil
	}

	if t.Status.Data.Resources, ok = claims["resources"].([]string); !ok {
		t.Status.Data.Resources = nil
	}

	if t.Status.Data.ResourceNames, ok = claims["resourceNames"].([]string); !ok {
		t.Status.Data.ResourceNames = nil
	}

	if t.Status.Data.NonResourceURLs, ok = claims["nonResourceURLs"].([]string); !ok {
		t.Status.Data.NonResourceURLs = nil
	}

	return t
}

func getRequstResource(request string) (namespace string, apiGroup string, resource string, resourceName string) {
	requestList := strings.Split(request, "/")

	// NOTE:
	// api/v1/RESOURCE/RESOURCE_NAME
	// api/v1/namespace/NAMESPACE/RESOURCE/RESOURCE_NAME
	// apis/GROUP/v1/RESOURCE/RESOURCE_NAME
	// apis/GROUP/v1/namespace/NAMESPACE/RESOURCE/RESOURCE_NAME
	// NON_REOURCE

	if len(requestList) >= 2 && requestList[0] == "api" {
		apiGroup = ""
		requestList = requestList[2:]
	} else {
		apiGroup = requestList[1]
		requestList = requestList[3:]
	}

	if len(requestList) >= 2 && requestList[0] == "namespace" {
		namespace = requestList[1]
		requestList = requestList[2:]
	}

	if len(requestList) >= 1 {
		resource = requestList[0]
	}

	if len(requestList) >= 2 {
		resourceName = requestList[1]
	}

	return
}

func getRequestVerb(requestMethod string) (string, bool) {
	verbMap := map[string]string{
		"POST":   "create",
		"GET":    "get",
		"HEAD":   "get",
		"PUT":    "update",
		"PATCH":  "patch",
		"DELETE": "delete",
	}

	// POST	     create
	// GET, HEAD get (for individual resources),
	//           list (for collections, including full object content),
	//           watch (for watching an individual resource or collection of resources)
	// PUT       update
	// PATCH     patch
	// DELETE    delete (for individual resources), deletecollection (for collections)

	verb, ok := verbMap[strings.ToUpper(requestMethod)]

	return verb, ok
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func containsWithPrefix(s []string, e string) bool {
	for _, a := range s {
		// Trim / from allowed paths
		a = strings.Trim(a, "/")

		// Check for partial match
		if strings.HasSuffix(a, "/*") && a[:len(a)-2] == e[:len(a)-2] {
			return true
		}

		// Check for exact match
		if a == e {
			return true
		}
	}
	return false
}

func containsWithAstrix(s []string, e string) bool {
	for _, a := range s {
		if a == "*" {
			return true
		}
		if a == e {
			return true
		}
	}
	return false
}

func authorizeTokenClamis(claims jwt.MapClaims, requestMethod string, requestAPIPath string) error {
	t := getTokenData(claims)
	verb, _ := getRequestVerb(requestMethod)
	namespace, apiGroup, resource, resourceName := getRequstResource(requestAPIPath)

	log.Printf("claims: [%+v]", t.Status.Data)
	log.Printf("request: %s [%s, %s, %s, %s]", verb, namespace, apiGroup, resource, resourceName)

	// Verifiy verb
	if t.Status.Data.Verbs == nil || !contains(t.Status.Data.Verbs, verb) {
		return fmt.Errorf("verb (%s) is not permited", verb)
	}

	// Check for NonResourceURLs
	if t.Status.Data.NonResourceURLs != nil && containsWithPrefix(t.Status.Data.NonResourceURLs, requestAPIPath) {
		return nil
	}

	// Verifiy namespace
	if t.Status.Data.Namespace != "*" && t.Status.Data.Namespace != namespace {
		return fmt.Errorf("namespace (%s) is not permited", namespace)
	}

	// Verify resource
	if t.Status.Data.APIGroups == nil {
		return fmt.Errorf("missing API APIGroups and NonResourceURLs")
	}

	if !containsWithAstrix(t.Status.Data.APIGroups, apiGroup) {
		return fmt.Errorf("apiGroup (%s) is not permited", apiGroup)
	}

	if t.Status.Data.Resources != nil && !containsWithAstrix(t.Status.Data.Resources, resource) {
		return fmt.Errorf("resource (%s) is not permited", resource)
	}

	if t.Status.Data.ResourceNames != nil && !containsWithAstrix(t.Status.Data.ResourceNames, resourceName) {
		return fmt.Errorf("resourceName (%s) is not permited", resourceName)
	}

	return nil
}
