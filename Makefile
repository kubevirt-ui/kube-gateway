SOURCE := cmd/kube-gateway/*.go pkg/proxy/*.go
IMG ?= quay.io/yaacov/kube-gateway
IMG_WEB_APP_NOVNC ?= quay.io/yaacov/kube-gateway-web-app-novnc
IMG_WEB_APP ?= quay.io/yaacov/kube-gateway-web-app

all: kube-gateway

kube-gateway: $(SOURCE)
	go build -v ./cmd/...

.PHONY: clean
clean:
	$(RM) kube-gateway

.PHONY: cleanall
cleanall:
	$(RM) kube-gateway
	$(RM) test/*
	$(RM) deploy/kube-gateway.yaml
	$(RM) deploy/kube-gateway.oauth2.yaml
	$(RM) deploy/kube-gateway.openshift.yaml

.PHONY: certs
certs:
	mkdir -p ./test
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=/emailAddress="
	kubectl get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

.PHONY: admin-token
admin-token:
	kubectl get secrets -n kube-gateway -o json | jq '[.items[] | select(.metadata.name | contains("kube-gateway-sa")) | select(.type | contains("service-account-token")) | .data.token][0]' | python -m base64 -d | tee test/token

.PHONY: novnc
novnc:
	git clone https://github.com/novnc/noVNC web/public/noVNC

.PHONY: image
image:
	podman build -t quay.io/yaacov/kube-gateway .
	podman push quay.io/yaacov/kube-gateway

.PHONY: image-web-app
image-web-app:
	podman build -t quay.io/yaacov/kube-gateway-web-app -f web-app.Dockerfile .
	podman push quay.io/yaacov/kube-gateway-web-app

.PHONY: image-web-app-novnc
image-web-app-novnc:
	podman build -t quay.io/yaacov/kube-gateway-web-app-novnc -f web-app-noVNC.Dockerfile .
	podman push quay.io/yaacov/kube-gateway-web-app-novnc

.PHONY: deploy-dir
deploy-dir:
	cd config/proxy && kustomize edit set image proxy=${IMG}
	cd config/proxy && kustomize edit set image web-app=${IMG_WEB_APP_NOVNC}
	kustomize build config/default > ./deploy/kube-gateway.yaml
	cd config/oauth2 && kustomize edit set image proxy=${IMG}
	cd config/oauth2 && kustomize edit set image web-app=${IMG_WEB_APP}
	kustomize build config/default.oauth2 > ./deploy/kube-gateway.oauth2.yaml
	cd config/openshift && kustomize edit set image proxy=${IMG}
	cd config/openshift && kustomize edit set image web-app=${IMG_WEB_APP_NOVNC}
	kustomize build config/default.openshift > ./deploy/kube-gateway.openshift.yaml

.PHONY: deploy
deploy: deploy-dir certs
	-kubectl create namespace kube-gateway
	-kubectl create secret generic kube-gateway-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem -n kube-gateway
	-kubectl apply -f ./deploy/kube-gateway.yaml

.PHONY: deploy-ouath2
deploy-ouath2: deploy-dir certs
	-kubectl create namespace kube-gateway
	-kubectl create secret generic kube-gateway-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem -n kube-gateway
	-kubectl apply -f ./deploy/kube-gateway.oauth2.yaml

.PHONY: deploy-openshift
deploy-openshift: deploy-dir certs
	-kubectl create namespace kube-gateway
	-kubectl create secret generic kube-gateway-jwt-secret --from-file=test/cert.pem --from-file=test/key.pem -n kube-gateway
	-kubectl apply -f ./deploy/kube-gateway.openshift.yaml

.PHONY: undeploy
undeploy:
	-kubectl delete -f ./deploy/kube-gateway.yaml
	-kubectl delete namespace kube-gateway

.PHONY: undeploy-ouath2
undeploy-ouath2:
	-kubectl delete -f ./deploy/kube-gateway.oauth2.yaml
	-kubectl delete namespace kube-gateway

.PHONY: undeploy-openshift
undeploy-openshift:
	-kubectl delete -f ./deploy/kube-gateway.openshift.yaml
	-kubectl delete namespace kube-gateway