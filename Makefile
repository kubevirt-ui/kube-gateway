SOURCE := cmd/oc-proxy/*.go pkg/proxy/*.go

all: oc-proxy

oc-proxy: $(SOURCE)
	go build -v ./cmd/...

.PHONY: clean
clean:
	$(RM) oc-proxy

.PHONY: cleanall
cleanall:
	$(RM) oc-proxy
	$(RM) test/*.pem
	$(RM) test/token
	$(RM) test/ca.crt

.PHONY: certificate
certificate:
	openssl genrsa -out test/key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650

.PHONY: secret
secret:
	oc create secret generic oc-proxy-jwt-secret --from-file=cert.pem

.PHONY: token
token:
	oc whoami -t > test/token

.PHONY: ca.crt
ca.crt:
	oc get secrets -n default --field-selector type=kubernetes.io/service-account-token -o json | jq '.items[0].data."ca.crt"' -r | python -m base64 -d > test/ca.crt

.PHONY: image
image:
	podman build -t yaacov/oc-proxy ./deploy
	podman tag yaacov/oc-proxy quay.io/yaacov/oc-proxy
	# podman push quay.io/yaacov/oc-proxy
