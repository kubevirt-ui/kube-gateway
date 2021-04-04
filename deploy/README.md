
# Deploy examples

## Deploy on minikube

```bash
# Using minikube with ingress and kubevirt addons
# minikube start --driver=podman --addons=kubevirt,ingress
minikube status
kubectl get pods --all-namespaces

# Create a virtual machine
kubectl apply -f https://raw.githubusercontent.com/kubevirt/demo/master/manifests/vm.yaml
virtctl start testvm

# Log into vm using ssh
virtctl expose vmi testvm --port=22 --name=myvm-ssh --type=NodePort

nodePort=$(kubectl get svc myvm-ssh -o json | jq .spec.ports[0].nodePort)
ssh cirros@api.crc.testing -p ${nodePort}

# Deploy k8s+kubevirt noVNC demo deployment:
make deploy
kubectl get ingress -n kube-gateway

# Wait for oc gate noVNC web application to deploy
kubectl get pods -n kube-gateway

# Get administarator token
bt=$(make admin-token -s)
echo $bt

# Set helper enviorment variables
vm=testvm
ns=default
apigroup=subresources.kubevirt.io
resource=virtualmachineinstances
path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/default/virtualmachineinstances/testvm/vnc
proxyurl=https://kube-gateway.apps.example.com

# Use admin token to request a temporary JWT access key
data='{"metadata":{"namespace":"kube-gateway"},"spec":{"namespace":"'${ns}'","apiGroups":["'${apigroup}'"],"resources":["'${resource}'"],"resourceNames":["'${vm}'"]}}'

# Use the admin token to create a temporary JWT access key for the testvm
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
oc get routes -n kube-gateway

# Start the web application, kube-gateway proxy automatically start oauth2 login
google-chrome https://kube-gateway.apps-crc.testing
```

### noVNC

```bash
# install kubevirt
KUBEVIRT_VERSION=$(curl -s https://github.com/kubevirt/kubevirt/releases/latest | grep -o "v[0-9]\.[0-9]*\.[0-9]*")
oc create -f https://github.com/kubevirt/kubevirt/releases/download/$KUBEVIRT_VERSION/kubevirt-operator.yaml
oc create -f https://github.com/kubevirt/kubevirt/releases/download/$KUBEVIRT_VERSION/kubevirt-cr.yaml

# Create a virtual machine
oc apply -f https://raw.githubusercontent.com/kubevirt/demo/master/manifests/vm.yaml
virtctl start testvm

# Deploy the openshift web application example
make deploy-openshift

# Get k8s admin token
bt=$(make admin-token -s)

# Set helper enviorment variables
vm=testvm
ns=default
apigroup=subresources.kubevirt.io
resource=virtualmachineinstances
path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/default/virtualmachineinstances/testvm/vnc
proxyurl=https://kube-gateway.apps-crc.testing

# Use admin token to request a temporary JWT access key
data='{"metadata":{"namespace":"kube-gateway"},"spec":{"namespace":"'${ns}'","apiGroups":["'${apigroup}'"],"resources":["'${resource}'"],"resourceNames":["'${vm}'"]}}'
jwt=$(curl -k -H 'Accept: application/json' -H "Authorization: Bearer ${bt}" -H "Content-Type: application/json" --request POST --data "${data}" "${proxyurl}/auth/gettoken" | jq .status.token)

# Open the noVNC web application using google-chrome
google-chrome  "${proxyurl}/auth/token?token=${jwt}&then=/noVNC/vnc_lite.html?path=${path}"
```
