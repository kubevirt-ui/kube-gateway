# oc-proxy

OC Proxy provides an interactive autenticating proxy to Kubernetes clusters.

- Proxying the Kubernetes API
- Serving frontend static assets
- Interactive user Authentication

## Example

``` bash
# git clone the source and cd into the base directory.

# Build oc-proxy
go build -o ./ ./cmd/oc-proxy/

# Create an oauthclient CR for the demo
oc create -f deploy/oauth-client-example.yaml

# Clont noVNC , we will use noVNC static html files to demo oc-proxy ability to mix static html with k8s api calls.
git clone https://github.com/novnc/noVNC

# Proxy the noVNC html files mixed with k8s API (replace the cluster with one you own)
# note that the proxy address must match the redirect address in the oauthclient CR we created
# earlier.
./oc-proxy \
   --api-path=/k8s \
   --public-dir ./noVNC/ \
   --listen http://0.0.0.0:8080 \
   --api-server https://api.ostest.test.metalkube.org:6443 \
   --base-address http://localhost:8080 \
   --skip-verify-tls
2021/02/25 01:47:30 Listening on http:0.0.0.0:8080

# Browse to a VM VNC (replace the vm name and namespace to one you can access with your credentials)
# export NAMESPACE=yzamir
# export NAME=rhel7-steep-cod
# http://localhost:8001/vnc_lite.html?path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/${NAMESPACE}/virtualmachineinstances/${NAME}/vnc
http://localhost:8080/vnc_lite.html?path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/yzamir/virtualmachineinstances/rhel7-steep-cod/vnc
```

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-proxy/main/img/demo.gif)

## Notes

### Compile and Test

``` bash
go test ./cmd/oc-proxy/
go build -o ./ ./cmd/oc-proxy/

./oc-proxy --help
./oc-proxy

./oc-proxy --public-dir ./ --listen https://0.0.0.0:8080
```

### Create self signed server certificate

``` bash
openssl ecparam -genkey -name secp384r1 -out key.pem
openssl req -new -x509 -sha256 -key key.pem -out cert.pem -days 3650
```

### Get clusters CA certificate

``` bash
oc get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > ca.crt
```

### Create an example OAuthClient

The exampe oauth-client will allow redirect to http[s]://localhost:8080/auth/callback endpoints.


``` bash
oc create -f deploy/oauth-client-example.yaml
```
