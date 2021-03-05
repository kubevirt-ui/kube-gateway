SOURCE := cmd/oc-gate/*.go pkg/proxy/*.go

all: oc-gate

oc-gate: $(SOURCE)
	go build -v ./cmd/...

.PHONY: clean
clean:
	$(RM) oc-gate

.PHONY: cleanall
cleanall:
	$(RM) oc-gate
	$(RM) test/*.pem
	$(RM) test/token
	$(RM) test/ca.crt

.PHONY: certificate
certificate:
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650

.PHONY: k8s-secret
k8s-secret:
	oc create -n oc-gate secret generic oc-gate-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem

.PHONY: k8s-oauth-client
k8s-oauth-client:
	oc create -f deploy/oc-gate-oauth-client.yaml

.PHONY: token
token:
	oc whoami -t > test/token

.PHONY: ca.crt
ca.crt:
	oc get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

.PHONY: novnc
novnc:
	git clone https://github.com/novnc/noVNC web/public/noVNC

.PHONY: image
image:
	podman build -t yaacov/oc-gate ./deploy
	podman tag yaacov/oc-gate quay.io/yaacov/oc-gate
	# podman push quay.io/yaacov/oc-gate
