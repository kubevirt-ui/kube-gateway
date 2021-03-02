
# Deploy

``` bash
oc create -f deploy/oc-proxy-template.yaml 
oc process -p ROUTE_URL=test-proxy.apps.ostest.test.metalkube.org oc-proxy | oc delete -f -

kubectl create secret generic oc-proxy-jwt-secret --from-file=./test/cert.pem

export TOKEN=$(echo {\"allowedAPIRegexp\":\"^/k8s/api/v1/pods/cert-manager-5597cff495-mb2v\"} | jwt -key test/key.pem -alg RS256 -sign -)
curl -k -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" https://test-proxy.apps.ostest.test.metalkube.org/k8s/api/v1/pods/cert-manager-5597cff495-mb2v | jq
```
