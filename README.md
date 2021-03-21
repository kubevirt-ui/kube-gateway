# oc-gate

![alt gopher network](https://raw.githubusercontent.com/yaacov/oc-gate/main/web/public/network-side.png)

OC Gate allows k8s users, with access to a list of objects, to give other users (or none k8s users) access to a sub-set of their objects for a limited time.

OC Gate can provide a filtering layer on top of k8s RABC that filter requests by validating time of request
and object name before passing them to k8s RBAC for final proccessing.

OC Gate can provide an OAuth2 interface, providing a login authentication interface with OAuth2 authentication issuer.

[![Go Report Card](https://goreportcard.com/badge/github.com/yaacov/oc-gate)](https://goreportcard.com/report/github.com/yaacov/oc-gate)
[![Go Reference](https://pkg.go.dev/badge/github.com/yaacov/oc-gate.svg)](https://pkg.go.dev/github.com/yaacov/oc-gate)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))

## Install

Using go install:

``` bash
go install github.com/yaacov/oc-gate/cmd/oc-gate
```

## Deploy

See deployment examples for minikube and code-ready-containrs in [deploy](https://github.com/yaacov/oc-gate/tree/main/deploy) 
``` bash
git clone git@github.com:yaacov/oc-gate.git
cd oc-gate

make deploy
```

## What can I do with it ?

- Create secure web applications leveraging the power of k8s API.
- Sublet access to your k8s resources for limited time, based on API path matching.

## Modes

- Non interative authentication using bearer JWT Authorization header.
- Interactive authentication using a OAuth2 authentication issuer.

### Proxy server endpoints

| endpoint | description
|---|----|
| / | web application static files |
| /auth/login | login path to start OAuth2 authentication process |
| /auth/callback | OAuth2 authentication callback endpoint |
| /auth/token | endpoint for setting session cookie |
| /auth/gettoken | endpoint for generating JWT access keys|
