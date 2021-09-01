
[![Go Report Card](https://goreportcard.com/badge/github.com/kubevirt-ui/kube-gateway)](https://goreportcard.com/report/github.com/kubevirt-ui/kube-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/kubevirt-ui/kube-gateway.svg)](https://pkg.go.dev/github.com/kubevirt-ui/kube-gateway)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# kube-gateway

![alt gopher network](https://raw.githubusercontent.com/kubevirt-ui/kube-gateway/main/docs/network-side.png)

Access the k8s API using time-limited access tokens. kube-gateway allows the usage of one-time access tokens to access k8s resources. Users
can use the default kube-gateway web application or create custom web applications that use the time-limited tokens to access the 
k8s API.

## What can I do with it?

- Create one-time links to access a k8s resource with a time-limited signed token (*).
- Create custom web applications that can access the k8s API using time-limited signed tokens.

(*) A signed token gives access to predefined k8s resources during a predefined time window.

## Build the gateway server with a noVNC web application

``` bash
# Build the gateway locally:
go build -v ./cmd/...

# Create and push the image into a container repository:
# For example:
# IMG=quay.io/kubevirt-ui/kube-gateway:v0.1.0 make image
IMG=<your image repo> make image

# `make image` builds and push the image, it is equivalent to running:
# podman build -t ${IMG} .
# podman push ${IMG}
```

## Build a custom web application using the gateway

Add your application to the [/web/public](./web/public) directory and create an image.

``` bash
# For example, copy your static web application to the ./web/public/ directory.
cp /dev/my-static-web-app/* ./web/public/

# Create a container image and push it to your container repository.
IMG=quay.io/myapps/custom-gateway:v0.0.1 make image
```

## Deploy service account, secrets, and route resources (when using OpenShift)

The [deploy](/deploy) directory contains example files to help create an example
service account with roles and secrets needed for running the gateway.

Running the gateway requires a service account that grants the gateway access to the k8s resources it
will proxy to the web application and secrets containing the public and private keys used to sign and 
verify the tokens.

``` bash
# Create a namespace for the gateway and service account using the deploy examples.
# The example files will create a namespace called kube-gateway and a service account granting
# reading privileges on the cluster. When deploying, users are encouraged to use minimal 
# privileges when creating a service account for the gateway proxy.
kubectl create -f deploy/namespace.yaml
kubectl create -f deploy/sa.yaml

# Generate public and private keys (the gateway supports RSA signatures with SHA-256 hashes)
openssl genrsa -out tls.key
openssl req -new -x509 -sha256 -key tls.key -out tls.crt -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="

# Create two secrets containing the private and public keys.
# NOTE: The service account running the gateway does not require access to the private key,
# but the public key must be accessible to the web application.
kubectl create secret generic kube-gateway-jwt --from-file=tls.crt -n kube-gateway
kubectl create secret generic kube-gateway-jwt-private --from-file=tls.key -n kube-gateway

# Create a serving certificate for the gateway TLS server.
# NOTE: There is no need to create this secret manually if you are using OpenShift, as it is 
#       created automatically in that case. 
kubectl create secret generic kube-gateway-secrets --from-file=tls.key --from-file=tls.crt -n kube-gateway

# Deploy the gateway in the example namespace using the example service account.
kubectl create -f deploy/kube-gateway.yaml
```

``` bash
# NOTE: On OpenShift, you can deploy the example route, but make
#       sure to edit the route to match your cluster's DNS.
oc create -f deploy/route.yaml
```

``` bash
# Check deployment and secrets.
kubectl get secrets -n kube-gateway
kubectl get pods -n kube-gateway
kubectl get svc -n kube-gateway

# On minikube, expose the service using:
# minikube service kube-gateway-svc -n kube-gateway
```

## Create a signed token

Obtain the k8s bearer token required to access the secret with the private key.

``` bash
# Obtain the token of the kube-gateway-sa service account (can read kube-gateway-jwt-private secret).
kubectl get secrets -n kube-gateway -o json | jq '[.items[] | select(.metadata.name | contains("kube-gateway-sa")) | select(.type | contains("service-account-token")) | .data.token][0]' | python -m base64 -d > token
```

``` bash
# Create a token payload.
# Available fields:
# URLs - The list of allowed APIs, a `*` postfix indicates any suffix is allowed
# duration - The duration for which the token will be valid (default is `1h`)
# from - The time the token will start to be valid in RFC3339 format. For example: "2016-11-01T20:44:39Z" (default is now)
# verbs - The list of allowed verbs. For example: ["get","post"] (default is ["get"])
data='{"URLs":["/api/*","/apis/*"],"duration":"30m"}'
token=$(cat token)
proxyurl=https://192.168.39.134:30345 # Use the URL of the gateway proxy

# Sign the token using the secret private key.
curl -sk -H 'Accept: application/json' -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/jwt/request" | jq .Token
```

## Create a signed link to access specific k8s resources

Once a token is signed it can be used to access the k8s API as long as it remains valid. Users can only access URLs specified in the token payload and only if the gateway service account can access them.

![alt vnc demo](https://raw.githubusercontent.com/kubevirt-ui/kube-gateway/main/docs/vnc-demo.gif)

In this example we will use the default noVNC web application.

``` bash
# The example noVNC application requires KubeVirt to be installed.
# On minikube, install KubeVirt using minikube addons. On other platforms, install
# KubeVirt in the manner recommended for that platform.
# minikube addons enable kubevirt

# Wait for KubeVirt to finish installing and then start the example virtual machine.
kubectl create -f deploy/vm.yaml

# Check that the virtual machine is running.
kubectl get vms -n kube-gateway
```

Now that the virtual machine is running, we can create a signed link to the KubeVirt noVNC server.

``` bash
# Copy the service account bearer token into a local file.
kubectl get secrets -n kube-gateway -o json | jq '[.items[] | select(.metadata.name | contains("kube-gateway-sa")) | select(.type | contains("service-account-token")) | .data.token][0]' | python -m base64 -d > token

# Create a path to the k8s resource.
path=/apis/subresources.kubevirt.io/v1/namespaces/kube-gateway/virtualmachineinstances/testvm/vnc

# Create a token payload for accessing the API path for 1 hour, starting now.
data="{\"URLs\":[\"${path}\"],\"duration\":\"1h\"}"
token=$(cat token) # Use a k8s token that can access the private key for signing the JWT

# On minikube get the url:
# minikube service kube-gateway-svc -n kube-gateway
# Important: the gateway is running with tls, make sure to use https:// 
proxyurl=https://192.168.39.134:30345 # Use the URL of the gateway proxy

# Use the /auth/jwt/request endpoint to sign the token payload using the private key secret.
# The service account bearer token used in this command must be able to access the secret holding the private key.
jwt=$(curl -sk -H 'Accept: application/json' -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/jwt/request" | jq .Token)

# Open the link in a browser.
# The link is signed using ${jwt} and will access the k8s API at ${path}.
signed_link="${proxyurl}/auth/jwt/set?token=${jwt}&then=/noVNC/vnc_lite.html?path=k8s${path}"

google-chrome "${signed_link}"
```

## Proxy server endpoints

| Endpoint | Requires | Description
|---|----|---|
| / | | web application static files |
| /auth/jwt/set | | endpoint for setting session JWT cookie |
| /login | ([/web/public/login](/web/public/login)) | helper page that sets the JWT token as a web browser cookie |
| /auth/login | flag `-oauth-server-enable` | login path to start the OAuth2 authentication process |
| /auth/callback | flag `-oauth-server-enable` | OAuth2 authentication callback endpoint |
| /auth/jwt/request | flag `-jwt-request-enable` | endpoint for generating JWT access keys |

## Supported JWT claims

| Claim | Example | Description  | Default |
|---|---|---|---|
|URLs | ["/api/v1/pods/*"] | list of allowed APIs, a `*` postfix indicates any suffix is allowed |
|duration | "25m" | the duration for which the token will be valid | "1h"
|from | "2016-11-01T20:44:39Z" | the time at which the token will start to be valid in RFC3339 format |  now
|verbs | ["get","post"] | list of allowed verbs  | ["get"]

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))
