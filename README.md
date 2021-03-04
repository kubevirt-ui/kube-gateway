## Steps to deploy on OCP cluster

1 - Create certs in a directory called test:

$ mkdir test
$
$ openssl genrsa -out test/key.pem
Generating RSA private key, 2048 bit long modulus (2 primes)
..............+++++
..............................+++++
e is 65537 (0x010001)


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
