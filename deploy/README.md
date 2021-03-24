
# Deploy examples

## Deploy on minikube

```bash
# Using minikube with ingress and kubevirt addons
# minikube start --driver=podman --addons=kubevirt,ingress
minikube status
k get pods --all-namespaces

# Create a virtual machine
kubectl apply -f https://raw.githubusercontent.com/kubevirt/demo/master/manifests/vm.yaml
virtctl start testvm

# Log into vm using ssh
virtctl expose vmi testvm --port=22 --name=myvm-ssh --type=NodePort

# Ceck the service noed port and replace <node port> with actual port
ssh cirros@api.crc.testing -p <node port>

# Deploy k8s+kubevirt noVNC demo deployment:
make deploy
k get ingress -n oc-gate

# Wait for oc gate noVNC web application to deploy
k get pods -n oc-gate

# Get administarator token
bt=$(make admin-token -s)
echo $bt

# Set some helper variables
vm=testvm
ns=default
path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/${ns}/virtualmachineinstances/${vm}/vnc
data='{"metadata":{"namespace":"oc-gate"},"spec":{"match-path":"^/'${path}'"}}'

# Use the admin token to create a temporary JWT access key for the testvm
proxyurl=https://oc-gate.apps.example.com
jwt=$(curl -k -H 'Accept: application/json' -H "Authorization: Bearer ${bt}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/gettoken" | jq .status.token)
echo $jwt

# Inject the temporary JWT and lounch novnc the web application
google-chrome  "${proxyurl}/auth/token?token=${jwt}&then=/noVNC/vnc_lite.html?path=${path}"
```

## Deploy on code ready containers

### Oauth2 (Interactive login)

``` bash
# Optional: set crc disk and mem sizes
crc config set disk-size 100
crc config set memory 12000
crc start

# Using crc
crc status
oc whoami
oc get pods --all-namespaces

# Deploy the OAuth2 demo web application
make deploy-ouath2 
oc get routes -n oc-gate

# Start the web application, oc-gate proxy automatically start oauth2 login
google-chrome https://oc-gate.apps-crc.testing
```

### noVNC

```bash
# install kubevirt
KUBEVIRT_VERSION=$(curl -s https://github.com/kubevirt/kubevirt/releases/latest | grep -o "v[0-9]\.[0-9]*\.[0-9]*")
oc create -f https://github.com/kubevirt/kubevirt/releases/download/$KUBEVIRT_VERSION/kubevirt-operator.yaml
oc create -f https://github.com/kubevirt/kubevirt/releases/download/$KUBEVIRT_VERSION/kubevirt-cr.yaml

# Create a virtual machine
k apply -f https://raw.githubusercontent.com/kubevirt/demo/master/manifests/vm.yaml
virtctl start testvm

# Deploy the openshift web application example
make deploy-openshift

# Set helper enviorment variables
vm=testvm
ns=default
path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/${ns}/virtualmachineinstances/${vm}/vnc
proxyurl=https://oc-gate.apps-crc.testing

# Get k8s admin token
bt=$(make admin-token -s)

# Use admin token to request a temporary JWT access key
data='{"metadata":{"namespace":"oc-gate"},"spec":{"match-path":"^/'${path}'"}}'
jwt=$(curl -k -H 'Accept: application/json' -H "Authorization: Bearer ${bt}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/gettoken" | jq .status.token)

# Open the noVNC web application using google-chrome
google-chrome  "${proxyurl}/auth/token?token=${jwt}&then=/noVNC/vnc_lite.html?path=${path}"
```
