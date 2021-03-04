## Steps to deploy on OCP cluster

#1 - Create certs

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
- allowedAPIMethods - string, comma seperated list of allowed API methods (e.g. is "get,post")
- allowedAPIRegexp - string, a reular expresion of allowed api call paths.

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
oc get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | \
    jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

# Create a public and private keys, this will be used to verify comunication with the oc-gate
# server, and to sign and verify JWT tokens.
# Note: use your own private and public keys if you already have them.
# Note II: oc-gate JWT verification only support RS265 RSA signiture algorithm
#          make sure you use rsa keys for the JWT creation and verification.
openssl genrsa -out test/key.pem
openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650

# Getting a service account token, the serive account token is stored in a secret matched
# to the service account.
# Note: this example use "oc cli" for shortcut, you can always use the secret to get the token.
oc whoami -t > test/token

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
oc-gate \
  --api-server https://api.ostest.test.metalkube.org:6443 \
  --k8s-bearer-token-passthrough true \
  --ca-file test/ca.crt

# Run without an OAuth2 server
# --jwt-token-key-file    : the public key used to verify JWT access tokens
# --k8s-bearer-token-file : the k8s token that will be used by the proxy to 
#                           fetch k8s resources for all verified users
oc-gate \
  --api-server https://api.ostest.test.metalkube.org:6443 \
  --k8s-bearer-token-file test/token \
  --jwt-token-key-file test/cert.pem \
  --skip-verify-tls
```

### Run the proxy locally using a container image

When running from container image replage the local CLI command `oc-gate` with a `podman run ...` call.

For example, after verifying that you have the `./test` dierctory with all the neccary certification,
you can run:

``` bash
# Run without an OAuth2 server
# --jwt-token-key-file    : the public key used to verify JWT access tokens
# --k8s-bearer-token-file : the k8s token that will be used by the proxy to 
#                           fetch k8s resources for all verified users
podman run -p 8080:8080 --privileged \
  --mount type=bind,source=test,target=/app/test \
  -it quay.io/yaacov/oc-gate \
  ./oc-gate \
  --api-server https://api.ostest.test.metalkube.org:6443 \
  --k8s-bearer-token-file test/token \
  --jwt-token-key-file test/cert.pem \
  --skip-verify-tls
```
