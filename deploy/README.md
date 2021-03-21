
# Deploy examples

## Deploy on minikube

```bash
# Using minikube with ingress and kubevirt addons
minikube status
k get pods --all-namespaces

# Create a virtual machine
k apply -f https://raw.githubusercontent.com/kubevirt/demo/master/manifests/vm.yaml
virtctl start testvm

# Deploy OC Gate noVNC demo deployment:
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

``` bash
# Using crc
crc status
oc whoami
oc get pods --all-namespaces

# Deploy OC Gate noVNC demo deployment
make deploy-ouath2 
oc get routes -n oc-gate

# Start the web application, oc-gate proxy automatically start oauth2 login
google-chrome https://oc-gate.apps-crc.testing
```
