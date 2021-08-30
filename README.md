
[![Go Report Card](https://goreportcard.com/badge/github.com/kubevirt-ui/kube-gateway)](https://goreportcard.com/report/github.com/kubevirt-ui/kube-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/kubevirt-ui/kube-gateway.svg)](https://pkg.go.dev/github.com/kubevirt-ui/kube-gateway)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# kube-gateway

![alt gopher network](https://raw.githubusercontent.com/kubevirt-ui/kube-gateway/main/docs/network-side.png)

Use k8s API for your web application, the k8s API is served in the same host as the web application,
the web application can manage the access control by manipolating a session cookie containing a singed token,
once the session cookie is set the web application can access the authorized k8s resources using k8s API.
A signed token gives access to predefined k8s resources during a predefined time window.

## What can I do with it ?

- Create links to access a k8s resource with a signed token (*).
- Create custom web applications that can access k8s API using singed tokens.

(*) a signed token that is authenticated using a public key gives access to predefined k8s resources during a predefined time window.
## Build the gateway server with noVNC web application

``` bash
# Build the gateway locally:
make

# Create and push the image into a container repository:
# For example
#IMG=quay.io/kubevirt-ui/kube-gateway:v0.1.0 make image
IMG=<your image repo> make image
```

## Build a custom web application using the gateway

Add you application to the [/web/public](./web/public) directory and create an image.

``` bash
# For example

# cCopy your static web application to the ./web/public/ dirctory
cp /dev/my-static-web-app/* ./web/public/

# Create a container image and push it into your container repository
IMG=quay.io/myapps/custom-gateway:v0.0.1 make image
```

## Deploy service account, secrets and route ( when using openshift )

The [deploy](/deploy) diretory contains example files to help create and example
service account with roles and secrets needed for running the gateway.

Running the gateway requires a service account the grants the gateway access to the k8s resources it
will proxy to the web application and secrets containing the public and private keys used to sign and 
verify the tokens.

``` bash
# Create a namespace for the gateway and service account, using the deploy examples
# The example files will create a namespace called kube-gateway and a service account granting
# cluster reading privileges, when deploying, users are encoraged to use minimalistic privileges
# when creating service account for the gateway proxy.
kubectl create -f deploy/namespace.yaml
kubectl create -f deploy/sa.yaml
```

``` bash
# Generate public and private keys (the gateway supports RSA Signature with SHA-256)
openssl genrsa -out tls.key
openssl req -new -x509 -sha256 -key tls.key -out tls.crt -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="

# Create two secrets containing the private and public keys,
# NOTE: the service account running the gateway does not reqiere access to the private key,
# the public key must be accessible to the web application.
kubectl create secret generic kube-gateway-jwt --from-file=tls.crt -n kube-gateway
kubectl create secret generic kube-gateway-jwt-private --from-file=tls.key -n kube-gateway

# Create a serving sertificats for the gateway TLS server
kubectl create secret generic kube-gateway-serving-cert --from-file=tls.key --from-file=tls.crt -n kube-gateway

# Deploy the gateway in the example namespace using the example service account
kubectl create -f deploy/kube-gateway.yaml
```

``` bash
# Check deploymet and secrets
kubectl get secrets -n kube-gateway
kubectl get pods -n kube-gateway
kubectl get svc -n kube-gateway

# On minikube, expose the service using
#minikube service kube-gateway-svc -n kube-gateway
```

## Create a singed token

Get the k8s bearer token required to access the secret with the private key.

``` bash
# Get the token of kube-gateway-sa service account (can read kube-gateway-jwt-private secret)
kubectl get secrets -n kube-gateway -o json | jq '[.items[] | select(.metadata.name | contains("kube-gateway-sa")) | select(.type | contains("service-account-token")) | .data.token][0]' | python -m base64 -d > token
```

``` bash
# Create a token payload
# Available fields:
# URLs - list of allowed API, a `*` postfix indicate any suffix is allowed
# duration - the duration to token will be valid (default is `1h`)
# from - RFC3339 time the token will start to be valid, for example "2016-11-01T20:44:39Z" (default is now)
# verbs - list of allowed verbs, for example ["get","post"] (default is ["get"])
data='{"URLs":["/api/*","/apis/*"],"duration":"30m"}'
token=$(cat token)
proxyurl=https://192.168.39.134:30345 # Use the url of the gateway proxy

# Sign the token using the secret private key
curl -sk -H 'Accept: application/json' -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/jwt/request" | jq .Token
```

## Create a signed link to access specific k8s resource

Once a token is signed it can be used to access the k8s API wile it is valid, users can only access URLs specified in the token payload, and only if the 
gateway service account can access them.

In this example we will use the default noVNC web application

``` bash
# The example noVNC application requirs kubevirt to be installed,
# on minikube install kubevirt using minikube addons, on other platforms install
# as recomended for that platform.
minikube addons enable kubevirt

# Wait for kubevirt to finish install and then
# start the example virtual machine
kubectl create -f deploy/vm.yaml

# check the virtual machien is running
kubectl get vms -n kube-gateway
```

Now that the virtual machine is running, we can create a signed link to kubevirt noVNC server.

``` bash
# Sign a token and put it in a variable
data='{"URLs":["/apis/subresources.kubevirt.io/v1/namespaces/kube-gateway/virtualmachineinstances/testvm/vnc"],"duration":"1h"}'
token=$(cat token) # Use a k8s token that can access the private key for signing the JWT
proxyurl=https://192.168.39.134:30345 # Use the url of the gateway proxy
jwt=$(curl -sk -H 'Accept: application/json' -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/jwt/request" | jq .Token)

# Create a path to the k8s resource
path=/apis/subresources.kubevirt.io/v1/namespaces/kube-gateway/virtualmachineinstances/testvm/vnc

# Open the link in a browser
# The link is sined using ${jwt} and will access the k8s API at ${path}
signed_link="${proxyurl}/auth/jwt/set?token=${jwt}&then=/noVNC/vnc_lite.html?path=k8s${path}"

google-chrome "${signed_link}"
```

## Proxy server endpoints

| endpoint | requirs | description
|---|----|---|
| / | | web application static files |
| /auth/jwt/set | | endpoint for setting session JWT cookie |
| /login | ([/web/public/login](/web/public/login)) | helper page that set the JWT token as a web borwser cookie |
| /auth/login | flag -oauth-server-enable | login path to start OAuth2 authentication process |
| /auth/callback | flag -oauth-server-enable | OAuth2 authentication callback endpoint |
| /auth/jwt/request | flag -jwt-request-enable | endpoint for generating JWT access keys |

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))
