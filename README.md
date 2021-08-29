
[![Go Report Card](https://goreportcard.com/badge/github.com/yaacov/kube-gateway)](https://goreportcard.com/report/github.com/yaacov/kube-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/yaacov/kube-gateway.svg)](https://pkg.go.dev/github.com/yaacov/kube-gateway)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# kube-gateway

![alt gopher network](https://raw.githubusercontent.com/yaacov/kube-gateway/main/docs/network-side.png)

Use k8s API for your web application. kube-gateway allow web application to connect to k8s API using signed tokens, without giving 
the web application users k8s accounts in the cluster, the signed tokens are specific to a k8s resource or resources and limited by time. 

## What can I do with it ?

- Create web applications that use k8s API, without giving users a user account in the cluster.
  (e.g. create a web application that allow authenticated users to access some k8s resource, without requiring users to also have k8s accounts)
- Allow external web application to create signed links that include a time limited token to access k8s resources.
  (e.g. send emails with a link that is valid for the next 3 hours and allow access to specific k8s resource)

## Build

Using go install:


``` bash
```

### Proxy server endpoints

| endpoint | requirs | description
|---|----|---|
| / | | web application static files |
| /auth/jwt/set | | endpoint for setting session JWT cookie |
| /login | ([/web/public/login](/web/public/login)) | helper page that set the JWT token as a web borwser cookie |
| /auth/login | flag -oauth-server-enable | login path to start OAuth2 authentication process |
| /auth/callback | flag -oauth-server-enable | OAuth2 authentication callback endpoint |
| /auth/jwt/request | flag -jwt-request-enable | endpoint for generating JWT access keys|

(gopher network image - [egonelbre/gophers](https://github.com/egonelbre/gophers))
