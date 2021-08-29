IMG ?= quay.io/kubevirt-ui/kube-gateway

all: kube-gateway

kube-gateway: cmd/kube-gateway/*.go pkg/proxy/*.go pkg/oauth/*.go pkg/token/*.go
	go build -v ./cmd/...

.PHONY: clean
clean:
	$(RM) kube-gateway
	$(RM) tls.key tls.crt ca.crt token

.PHONY: certs
certs:
	openssl genrsa -out tls.key
	openssl req -new -x509 -sha256 -key tls.key -out tls.crt -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="

.PHONY: sa
sa: certs
	kubectl create -f deploy/sa.yaml
	kubectl create secret generic kube-gateway-jwt --from-file=tls.crt -n kube-gateway
	kubectl create secret generic kube-gateway-jwt-private --from-file=tls.key -n kube-gateway

.PHONY: ca
ca:
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > ca.crt

.PHONY: token
token:
	kubectl get secrets -n kube-gateway -o json | jq '[.items[] | select(.metadata.name | contains("kube-gateway-sa")) | select(.type | contains("service-account-token")) | .data.token][0]' | python -m base64 -d > token

.PHONY: image
image:
	podman build -t ${IMG} .
	podman push ${IMG}
