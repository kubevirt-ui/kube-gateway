# oc-gate

![alt gopher network](https://raw.githubusercontent.com/yaacov/oc-gate/main/web/public/network-side.png)

It allows k8s users, with access to a list of objects, to give other users (or none k8s users) access to a sub-set of their objects for a limited time.

OC Gate provide a filtering layer on top of k8s RABC that filter requests by validating time of request
and object name before passing them to k8s RBAC for final proccessing.

[![Go Report Card](https://goreportcard.com/badge/github.com/yaacov/oc-gate)](https://goreportcard.com/report/github.com/yaacov/oc-gate)
[![Go Reference](https://pkg.go.dev/badge/github.com/yaacov/oc-gate.svg)](https://pkg.go.dev/github.com/yaacov/oc-gate)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))

## Install

Using go install:

``` bash
go install github.com/yaacov/oc-gate/cmd/oc-gate
```

## Deploy using an operator

See [oc-gate-operator](https://github.com/yaacov/oc-gate-operator) for cluster deployment.

## What can I do with it ?

- Create secure web applications leveraging the power of k8s API.
- Sublet access to your k8s resources for limited time, based on API path matching.

![Peek 2021-03-06 21-57](https://user-images.githubusercontent.com/2181522/110219350-4c61c680-7ec7-11eb-822f-e6073bd11c6c.gif)

The above screencast use [oc-gate-operator](https://github.com/yaacov/oc-gate-operator) ro create the tokens.

## Modes

- Interactive authentication using a OAuth2 authentication issuer.
- Non interative authentication using bearer JWT Authorization header.

## Running using ODK internal OAuth2 server

When running using OKD (Openshift) OAuth issuer, operator does not need to provide a k8s service acount token,
the internal OAuth2 server will issue tokens that can be verified by the cluster.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-gate/main/web/public/using_okd_oauth.gif)

## Verifying RSA signed JWT authentication tokens

In this configuration an operator will create signed expiring JWT tokens that will
allow access to specific cluster resources. The proxy will verify the JWT using a
public key, and allow access acording to TWJ claims. If JWT is cerified and the requested
k8s object match JWT claims, the proxy will use it's own service acount to do the request.

Allowed JWT claims are:

- exp - int, expiration (unix time)
- nbf - int, not before (unix time)
- matchMethod - string, comma seperated list of allowed API methods (e.g. is "get,post")
- matchPath - string, a reular expresion of allowed api call paths.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-gate/main/web/public/custom_tokens.gif)

## Compile and run

``` bash
go build -o ./ ./cmd/oc-gate/

./oc-gate --help
```

## Examples

See [deploy/README.md](/deploy) for cluster deployment set examples.

### Get some pre requirments

```bash
# Get the k8s API CA, this is used for secure comunication with the server.
# Note: you can use "-skip-verify-tls" flag to comunicate unsecurly with server
# instead of fetching this file.
kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | \
    jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

# Create RSA256 pem private and private key pair, this will be used to verify comunication with the oc-gate
# server, and to sign and verify JWT tokens.
openssl genrsa -out test/key.pem
openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650

# Getting a service account token, the serive account token is stored in a secret matched
# to the service account.
# Note: this example use "oc cli" for shortcut, you can always use the secret to get the token.
kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | \
    jq '.items[0].data."token"'

# For the noVNC demo, you can git clone the noVNC static html files into the `web/public`
# directory
git clone https://github.com/novnc/noVNC web/public/noVNC
```

### Run the proxy locally

Make sure you have all the pre-required certifations in the test directory.

``` bash
# Proxy the noVNC html files mixed with k8s API (replace the cluster with one you own)
# note that the proxy address must match the redirect address in the oauthclient CR we created
# earlier.
# --api-server : the k8s API server, this command assumes this cluster is an OKD (Openshift) cluster
#                and the proxy will look up it's OAuth server automatically and pass tokens provided
#                by the internal authentication issuer directly to the cluster.
#                for example --api-server=https://api.ostest.test.metalkube.org:6443
oc-gate \
  --api-server $(oc whoami --show-server) \
  --k8s-bearer-token-passthrough true \
  --ca-file test/ca.crt

# Run without an OAuth2 server
# --jwt-token-key-file    : the public key used to verify JWT access tokens
# --k8s-bearer-token-file : the k8s token that will be used by the proxy to 
#                           fetch k8s resources for all verified users
oc-gate \
  --api-server $(oc whoami --show-server) \
  --k8s-bearer-token-file test/token \
  --jwt-token-key-file test/cert.pem \
  --skip-verify-tls
```

### Special paths

- /auth/login - login path to start OAuth2 authentication process.
- /auth/callback - OAuth2 authentication callback endpoint.
- /auth/token - endpoint for setting session cookie, this query parameters are available:
  - token - the value to push into the session cookie
  - then - path to redirect to after cookie is set
