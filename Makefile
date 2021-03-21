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
	$(RM) test/*

.PHONY: certs
certs:
	mkdir -p ./test
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."token"' -r | python -m base64 -d > test/token

.PHONY: secret
secret:
	oc create -n oc-gate secret generic oc-gate-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem --from-file=test/token --from-file=test/ca.crt

.PHONY: novnc
novnc:
	git clone https://github.com/novnc/noVNC web/public/noVNC

.PHONY: image
image:
	podman build -t quay.io/yaacov/oc-gate .
	podman push quay.io/yaacov/oc-gate

.PHONY: image-web-app
image-web-app:
	podman build -t quay.io/yaacov/oc-gate-web-app -f web-app.Dockerfile .
	podman push quay.io/yaacov/oc-gate-web-app

.PHONY: image-web-app-novnc
image-web-app-novnc:
	podman build -t quay.io/yaacov/oc-gate-web-app-novnc -f web-app-noVNC.Dockerfile .
	podman push quay.io/yaacov/oc-gate-web-app-novnc