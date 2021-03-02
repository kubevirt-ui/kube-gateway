# oc-proxy

![alt gopher network](https://raw.githubusercontent.com/yaacov/oc-proxy/main/web/public/network-side.png)

OC Proxy provides an interactive and non-interactive authentication proxy to [Kubernetes](https://kubernetes.io/) clusters.
OC Proxy use [JWT](https://jwt.io/) (HS256, RS256) tokens for user authorization.

[![Go Report Card](https://goreportcard.com/badge/github.com/yaacov/oc-proxy)](https://goreportcard.com/report/github.com/yaacov/oc-proxy)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))

## Install

Using go install:

``` bash
go install github.com/yaacov/oc-proxy/cmd/oc-proxy
```

Using container image:

``` bash
podman run -p 8080:8080 --privileged --mount type=bind,source=test,target=/app/test -it quay.io/yaacov/oc-proxy ./oc-proxy -api-server <URL of k8s API server>
```

## What can I do with it ?

- Create secure web applications leveraging the power of k8s API.
- Sublet access to your k8s resources for limited time, based on API path matching.

## Modes

- Interactive authentication using a OAuth2 authentication issuer.
- Non interative authentication using bearer JWT Authorization header.

## Running using ODK internal OAuth2 server

When running using OKD (Openshift) OAuth issuer, operator does not need to provide a k8s service acount token,
the internal OAuth2 server will issue tokens that can be verified by the cluster.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-proxy/main/web/public/using_okd_oauth.gif)

## Verifying RSA signed JWT authentication tokens

In this configuration an operator will create signed expiring JWT tokens that will
allow access to specific cluster resources. The proxy will verify the JWT using a
public key, and allow access acording to TWJ claims. If JWT is cerified and the requested
k8s object match JWT claims, the proxy will use it's own service acount to do the request.

Allowed JWT claims are:

- exp - int, expiration (unix time)
- nbf - int, not before (unix time)
- allowedAPIMethods - string, comma seperated list of allowed API methods (e.g. is "get,post")
- allowedAPIRegexp - string, a reular expresion of allowed api call paths.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-proxy/main/web/public/custom_tokens.gif)

## Compile and run

``` bash
go build -o ./ ./cmd/oc-proxy/

./oc-proxy --help
```

## Examples

See the [deploy](/deploy) directory for more details deploy examples.

``` bash
# Proxy the noVNC html files mixed with k8s API (replace the cluster with one you own)
# note that the proxy address must match the redirect address in the oauthclient CR we created
# earlier.
# --api-server : the k8s API server, this command assumes this cluster is an OKD (Openshift) cluster
#                and the proxy will look up it's OAuth server automatically and pass tokens provided
#                by the internal authentication issuer directly to the cluster.
./oc-proxy --api-server https://api.ostest.test.metalkube.org:6443

# Run without an OAuth2 server
# --jwt-token-key-file : the public key used to verify JWT access tokens
# --k8s-bearer-token   : the k8s token that will be used by the proxy to fetch k8s resources for all
#                        verified users
./oc-proxy \
    --api-server <your k8s API server URL> \
    --skip-verify-tls \
    --oauth-server-disable \
    --jwt-token-key-file test/crt.pem \
    --k8s-bearer-token $TOKEN
```
