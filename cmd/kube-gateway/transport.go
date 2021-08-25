package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/glog"
)

// GetTLSTranport creats a http transport for comunication with k8s cluster
func GetTLSTranport(skipVerifyTLS *bool, apiServerCAFile *string) *http.Transport {
	var transport *http.Transport

	if *skipVerifyTLS {
		glog.Info("skip TSL verify when connecting to k8s server")

		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 30 * time.Second,
		}
	} else if *apiServerCAFile != "" {
		glog.Infof("use CA File [%s] file when connecting to k8s server", *apiServerCAFile)

		k8sCertPEM, err := ioutil.ReadFile(*apiServerCAFile)
		if err != nil {
			LogErrorAndExit(err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(k8sCertPEM) {
			LogErrorAndExit(fmt.Errorf("no CA found for the API server in file %s", *apiServerCAFile))
		}
		transport = &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: rootCAs},
			TLSHandshakeTimeout: 30 * time.Second,
		}
	} else {
		glog.Info("use system's Root CAs when connecting to k8s server (use -ca-file to specify a specifc certification file or -skip-verify-tls for insecure connection)")

		transport = &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		}
	}

	return transport
}
