SOURCE := cmd/oc-gate/*.go pkg/proxy/*.go
IMG ?= quay.io/yaacov/oc-gate
IMG_WEB_APP ?= quay.io/yaacov/oc-gate-web-app

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
	$(RM) deploy/oc-gate.yaml

.PHONY: certs
certs:
	mkdir -p ./test
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."token"' -r | python -m base64 -d > test/token

.PHONY: oc-gate-token
oc-gate-token:
	kubectl get secrets -n oc-gate -o json | jq '.items[] | select(.metadata.name | contains("sa")) | .data.token' | python -m base64 -d

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

.PHONY: deploy-dir
deploy-dir:
	cd config/proxy && kustomize edit set image proxy=${IMG}
	cd config/proxy && kustomize edit set image web-app=${IMG_WEB_APP}
	kustomize build config/default > ./deploy/oc-gate.yaml

.PHONY: deploy
deploy: deploy-dir
	kubectl create namespace oc-gate
	kubectl create secret generic oc-gate-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem --from-file=test/token --from-file=test/ca.crt -n oc-gate 
	kubectl apply -f ./deploy/oc-gate.yaml

.PHONY: undeploy
undeploy:
	kubectl delete -f ./deploy/oc-gate.yaml
	kubectl delete secret oc-gate-jwt-secret -n oc-gate 
	kubectl delete namespace oc-gate
