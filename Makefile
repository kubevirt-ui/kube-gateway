SOURCE := cmd/oc-gate/*.go pkg/proxy/*.go
IMG ?= quay.io/yaacov/oc-gate
IMG_WEB_APP ?= quay.io/yaacov/oc-gate-web-app-novnc

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
	$(RM) deploy/oc-gate.openshift.yaml

.PHONY: certs
certs:
	mkdir -p ./test
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

.PHONY: token
token:
	kubectl get secrets -n oc-gate -o json | jq '.items[] | select(.metadata.name | contains("sa")) | .data.token' | python -m base64 -d | tee test/token -

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
	cd config/oauth2 && kustomize edit set image proxy=${IMG}
	cd config/oauth2 && kustomize edit set image web-app=${IMG_WEB_APP}
	kustomize build config/openshift > ./deploy/oc-gate.openshift.yaml

.PHONY: deploy
deploy: deploy-dir certs
	-kubectl create namespace oc-gate
	-kubectl create secret generic oc-gate-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem -n oc-gate
	-kubectl apply -f ./deploy/oc-gate.yaml

.PHONY: undeploy
undeploy:
	-kubectl delete -f ./deploy/oc-gate.yaml
	-kubectl delete namespace oc-gate
