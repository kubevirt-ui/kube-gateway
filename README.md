![alt gopher network](https://raw.githubusercontent.com/yaacov/oc-proxy/main/web/public/network-side.png)

# oc-proxy

OC Proxy provides an interactive and non-interactive authentication proxy to [Kubernetes](https://kubernetes.io/) clusters, using [OAuth2](https://oauth.net/2/) authentication issuer, 
and bearer [JWT](https://jwt.io/) (HS256, RS256) Authorization header.

[![Go Report Card](https://goreportcard.com/badge/github.com/yaacov/oc-proxy)](https://goreportcard.com/report/github.com/yaacov/oc-proxy)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## What can I do with it ?

- Create secure web applications leveraging the power of k8s API using interactive OAuth authentication.
- "Sublet" access to your k8s resources for limited time based on API path, to users who o/w do not have access to them.

## Modes

- Interactive authentication using a OAuth2 authentication issuer.
- Interactive authentication using the inernal OKD (Openshift) authentication issuer.
- Non interative authentication using bearer JWT Authorization header.

### Running using ODK internal OAuth2 server

When running using OKD (Openshift) OAuth issuer, operator does not need to provide a user token,
the internal OAuth2 server will issue tokens that can be verified by the cluster.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-proxy/main/web/public/using_okd_oauth.gif)


### Verifying RSA signed JWT authentication tokens

When using custom tokens, operator will provide a k8s token to access the k8s API.
In this configuration an operator will create JWT expiring payloads that will restrict access to cluster resources,
then sign the token using a private key.
The proxy will verify the JWT using a public key, and restrict access acording the the recived JWT specification.
The proxy will allow only requests that match the JWT restrictions and use the operator provider k8s token to fetch the
data from the cluster.
Allowed JWT claims are:

- exp - unix time of token expiration
- allowedAPIMethods - comma seperated list of allowed API methods (default is "get,options")
- allowedAPIRegexp - a reular expresion of allowed api call paths.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-proxy/main/web/public/custom_tokens.gif)

## Features

- Proxying the Kubernetes API.
- Serving frontend static assets.
- Interactive user Authentication, using OAuth2 server.
- Non interactive Bearer token Authentication.
- oc-proxy can proxy WebSockets, the [noVNC](https://novnc.com/) demo shows WebSocket access to [kubevirt](https://kubevirt.io/) viertual machines noVNC server.
- oc-proxy can get an access token via [Openshifts OAuth2 server](https://docs.openshift.com/container-platform/4.7/authentication/configuring-internal-oauth.html), if this OAuth2 server is used, the proxy will not require a pre existing token to run, the server is installed by default on [OKD](https://www.okd.io/) k8s clusters.

The proxy will validate JWT bearer tokens check for "allowedAPIMethods" and "allowedAPIRegexp" claims, and if token and request are valid,
send an API request using the proxy-known k8s token.

## Compile and run

``` bash
go build -o ./ ./cmd/oc-proxy/

./oc-proxy --help
```

## Example using OKD internal OAuth server

``` bash
# git clone the source and cd into the base directory.

# Build oc-proxy
go build -o ./ ./cmd/oc-proxy/

# Create an oauthclient CR for the demo
oc create -f deploy/oauth-client-example.yaml

# Creat self signed certificate (needed if server use TLS)
openssl genrsa -out key.pem
openssl req -new -x509 -sha256 -key key.pem -out cert.pem -days 3650

# get the API server CA certificate (can be skipped by using --skip-verify-tls flag)
oc get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > ca.crt

# For the noVNC demo clone noVNC html files, (this demo requires kubevirt installed on the server)
# we will use noVNC static html files to demo oc-proxy ability to mix static html with k8s api calls.
git clone https://github.com/novnc/noVNC web/public/noVNC

# Proxy the noVNC html files mixed with k8s API (replace the cluster with one you own)
# note that the proxy address must match the redirect address in the oauthclient CR we created
# earlier.
./oc-proxy --api-server https://api.ostest.test.metalkube.org:6443

# Browse to a VM VNC (replace the vm name and namespace to one you can access with your credentials)
# export NAMESPACE=yzamir
# export NAME=rhel7-steep-cod
# https://localhost:8080/noVNC/vnc_lite.html?path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/${NAMESPACE}/virtualmachineinstances/${NAME}/vnc
https://localhost:8080/noVNC/vnc_lite.html?path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/yzamir/virtualmachineinstances/rhel7-steep-cod/vnc
```

## Example using custom JWT access tokens

``` bash
# When running without the internal OAuth server, operator must supply a valid k8s token
# This token will be used to fetch resources from the cluster API when the proxy
# validates the JWT and apply the restrictions
export TOKEN=<the operator k8s token that will be used to fetch data from the cluster>

# Run without an OAuth2 server
./oc-proxy \
    --api-server <your k8s API server URL> \
    --skip-verify-tls \
    --oauth-server-disable \
    --jwt-token-key-file test/crt.pem \
    --k8s-bearer-token $TOKEN

# Creat self signed certificate (needed for signing and verifying JWT payload)
openssl genrsa -out key.pem
openssl req -new -x509 -sha256 -key key.pem -out cert.pem -days 3650

# Create a token with path restriction,
# oc-proxy will check "exp", "allowedAPIMethods" and "allowedAPIRegexp" claims 
echo {\"allowedAPIRegexp\":\"^/k8s/api/v1/pods\"} | jwt -key ./test/key.pem -alg RS256 -sign -

# Create a token with experation date
echo {\"exp\": $(expr $(date +%s) + 100)} | jwt -key ./deploy/secret -alg HS256 -sign -

# Use bearer authentication
# The token will be validated and the "allowedAPIRegexp" claim will be checked agains the API call path
export TOKEN=<the signed token>
curl -k -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" https://localhost:8080/k8s/api/v1/pods/cert-manager-5597cff495-mb2vx | jq
```
