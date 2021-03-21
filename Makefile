SOURCE := cmd/oc-gate/*.go pkg/proxy/*.go
IMG ?= quay.io/yaacov/oc-gate
IMG_WEB_APP_NOVNC ?= quay.io/yaacov/oc-gate-web-app-novnc
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
	$(RM) deploy/oc-gate.openshift.yaml

.PHONY: certs
certs:
	mkdir -p ./test
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

.PHONY: admin-token
admin-token:
	kubectl get secrets -n oc-gate -o json | jq '[.items[] | select(.metadata.name | contains("oc-gate-sa")) | select(.type | contains("service-account-token")) | .data.token][0]' | python -m base64 -d | tee test/token

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
	cd config/proxy && kustomize edit set image web-app=${IMG_WEB_APP_NOVNC}
	kustomize build config/default > ./deploy/oc-gate.yaml
	cd config/oauth2 && kustomize edit set image proxy=${IMG}
	cd config/oauth2 && kustomize edit set image web-app=${IMG_WEB_APP}
	kustomize build config/openshift > ./deploy/oc-gate.oauth2.yaml

.PHONY: deploy
deploy: deploy-dir certs
	-kubectl create namespace oc-gate
	-kubectl create secret generic oc-gate-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem -n oc-gate
	-kubectl apply -f ./deploy/oc-gate.yaml

.PHONY: deploy-ouath2
deploy-ouath2: deploy-dir certs
	-kubectl create namespace oc-gate
	-kubectl create secret generic oc-gate-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem -n oc-gate
	-kubectl apply -f ./deploy/oc-gate.oauth2.yaml

.PHONY: undeploy
undeploy:
	-kubectl delete -f ./deploy/oc-gate.yaml
	-kubectl delete namespace oc-gate

.PHONY: undeploy-ouath2
undeploy-ouath2:
	-kubectl delete -f ./deploy/oc-gate.oauth2.yaml
	-kubectl delete namespace oc-gate