
# Deploy on a cluster

## Before you start

This folder include demo deploy files that happily use non specific RBAC roles, please do not use them on none dev/testing env.

## Deploy

Create public and private keys for signing and verifiying JWT tokens

``` bash
# Creat self signed certificate (needed if server use TLS)
openssl genrsa -out test/key.pem
openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650
```

Create a secret holding a public key for verification of JWT tokens

``` bash
# We can use the same key as the server, or create a new pair just for JWT tokens.
kubectl create secret generic oc-gate-jwt-secret --from-file=test/cert.pem
```

For interactive type of deploy create an oauthclient k8s object

``` bash
# Create a new client for the clusters OAuth2 server.
# OKD (Openshift) install an OAuth2 server on new clusters by default.
# Note: on k8s cluters without OKD, you will need to use a different
# OAuth server.
oc create -f deploy/oc-gate-oauth-client.yaml
```

Use the example template to deploy the proxy server

``` bash
# Create the example namespace
oc new-project oc-gate

# Note: templates are an OKD thing, if running on k8s cluster without OKD
# you will neen to install the objects using a different method.
oc create -f deploy/oc-gate-template.yaml 

# The template requires the HOST of the oc-gate server.
# for example: ROUTE_URL=test-proxy.apps.ostest.test.metalkube.org
# Note: routes are OKD thing too, OKD install a default proxy / loadbalancer
# that route outside requests to k8s services.
oc process -p ROUTE_URL=<the HOST of your oc-gate> oc-gate | oc create -f -

# For interactive deploy using OKD OAuth2 default server, use bearer token pass through.
oc process -p ROUTE_URL=<the HOST of your oc-gate> oc-gate -p TOKEN_PASSTHROUGH=true | oc create -f -
```

## Create a token, and fetch k8s objects using it

Create a JWT specific for the k8s object you want to allow holder of this JWT to access:

``` bash
# To sign the JWT use the private key that belong to the public key in the running oc-gate
# The "allowedAPIRegexp" claim use regexp to allow specific k8s path
# use '^' to force start of path, and '$' to force end of path.
# Other claims the proxy will respect are: allowedAPIMethods, exp and nbf

# Create a token with path restriction,
echo {\"allowedAPIRegexp\":\"^/k8s/api/v1/pods\"} | jwt -key ./test/key.pem -alg RS256 -sign -

# Create a token with experation date and allowed API path
echo {\"exp\": $(expr $(date +%s) + 100),\"allowedAPIRegexp\":\"^/k8s/api/v1/namespaces/test\"} | jwt -key ./test/key.pem -alg RS256 -sign -
```

This token can now be given to a user that will have access only to this specific k8s object(s).

``` bash
# A user of this token can now send requests to the oc-gate using the new JWT
# If the JWT is authentic, did not expire (if exp or nbf claims are used), and match the allowed path -
# the proxy will replace the JWT with the token of the service account running the proxy,
# Depending on k8s RBAC rulls the object will be fetched or not.
curl -k -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" https://<route to your oc gate>/k8s/<API path of k8s object> | jq
```

### jwt CLI tool

The examples above use this CLI tool to create and sign the JWT tokens, any other tool will do too:

[dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go/tree/master/cmd/jwt)
