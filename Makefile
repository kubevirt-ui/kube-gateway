SOURCE := cmd/oc-proxy/*.go pkg/proxy/*.go

all: oc-proxy

oc-proxy: $(SOURCE)
	go build -v ./cmd/...

.PHONY: clean
clean:
	$(RM) oc-proxy

.PHONY: certificate
certificate:
	openssl genrsa -out key.pem
	openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650

.PHONY: secret
secret:
	oc create secret generic oc-proxy-jwt-secret --from-file=cert.pem

.PHONY: image
image:
	podman build -t yaacov/oc-proxy ./deploy
	podman tag yaacov/oc-proxy quay.io/yaacov/oc-proxy
	# podman push quay.io/yaacov/oc-proxy
