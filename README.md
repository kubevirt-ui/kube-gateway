# Steps to deploy oc-gate on OCP cluster

## 1 - Create test dir and populate it with SSL certs:
$ mkdir test

$ openssl genrsa -out test/key.pem
``` bash
Generating RSA private key, 2048 bit long modulus (2 primes)
..............+++++
..............................+++++
e is 65537 (0x010001)
$
```

$ openssl req -new -x509 -sha256 -key test/key.pem -out test/cert.pem -days 3650
``` bash
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [US]:
State or Province Name (full name) []:
Locality Name (eg, city) [Default City]:
Organization Name (eg, company) [Default Company Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:
Email Address []:
$
```

$ ls test
``` bash
cert.pem  key.pem
$
```

## 2- Login into OCP cluster to deploy oc-gate app:
$ oc login https://api.ocp4.xxx.xxx:6443
``` bash
Authentication required for https://api.ocp4.xxx.xxx:6443 (openshift)
Username: xxxx
Password: 
Login successful.

You have access to xx projects, the list has been suppressed. You can list all projects with ' projects'

Using project "default".
$
```

## 3- Create oc-gate project:
$ oc new-project oc-gate
``` bash
Now using project "oc-gate" on server "https://api.xxx.xxx.lab:6443".

You can add applications to this project with the 'new-app' command. For example, try:

    oc new-app rails-postgresql-example

to build a new example application in Ruby. Or use kubectl to deploy a simple Kubernetes application:

    kubectl create deployment hello-node --image=k8s.gcr.io/serve_hostname
$
```

## 4- Create a new secret oc-gate-jwt-secret in the oc-gate project:
$ oc create secret generic oc-gate-jwt-secret --from-file=test/cert.pem
``` bash
secret/oc-gate-jwt-secret created
```



## Running using ODK internal OAuth2 server

When running using OKD (Openshift) OAuth issuer, operator does not need to provide a k8s service acount token,
the internal OAuth2 server will issue tokens that can be verified by the cluster.

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-gate/main/web/public/using_okd_oauth.gif)

## Verifying RSA signed JWT authentication tokens

![alt demo gif](https://raw.githubusercontent.com/yaacov/oc-gate/main/web/public/custom_tokens.gif)

## Compile and run

``` bash
go build -o ./ ./cmd/oc-gate/

./oc-gate --help
```
