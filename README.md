# kube-gateway

![alt gopher network](https://raw.githubusercontent.com/yaacov/kube-gateway/main/web/public/network-side.png)

Kube gateway allow web applications running inside (or outside) a k8s cluster to use autheticated calls to k8s API.

Kube gateway can provide a filtering layer on top of k8s RABC that filter requests by validating time of request
and object name before passing them to k8s RBAC for final proccessing.

Kube gateway can provide a login authentication interface with OAuth2 authentication issuer.

[![Go Report Card](https://goreportcard.com/badge/github.com/yaacov/kube-gateway)](https://goreportcard.com/report/github.com/yaacov/kube-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/yaacov/kube-gateway.svg)](https://pkg.go.dev/github.com/yaacov/kube-gateway)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))

## Install

Using go install:

``` bash
go install github.com/yaacov/kube-gateway/cmd/kube-gateway
```

## What can I do with it ?

- Create web applications that use k8s API securly.
- Use temporary JWT keys to access k8s API.
- Use OAuth2 Issuer to access k8s API.
- Use k8s service account tokens to access k8s API.

### Demo: use JWT access key to none-interactivly login into a k8s web application

Deploy the noVNC web application on a minikube cluster.
Use admin token to generate a JWT that can access a kubevirt virtuall machine for 1h.
Use the JWT access key to login into the noVNC web application.

![alt demo gif](https://raw.githubusercontent.com/yaacov/kube-gateway/main/web/public/novnc.gif)

### Demo: use OAuth2 Issuer to interactivly login into a k8s web application

Deploy the demo web application on a CRC cluster.
Use OAuth2 Issuer to login into the demo web application.

![alt demo gif](https://raw.githubusercontent.com/yaacov/kube-gateway/main/web/public/oauth.gif)

## Deploy

See deployment examples for minikube and code-ready-containrs in [deploy](https://github.com/yaacov/kube-gateway/tree/main/deploy) 

``` bash
git clone git@github.com:yaacov/kube-gateway.git
cd kube-gateway

make deploy
```

### Proxy server endpoints

| endpoint | description
|---|----|
| / | web application static files |
| /auth/login | login path to start OAuth2 authentication process |
| /auth/callback | OAuth2 authentication callback endpoint |
| /auth/token | endpoint for setting session cookie |
| /auth/gettoken | endpoint for generating JWT access keys|
