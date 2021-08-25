package main

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/kubevirt-ui/kube-gateway/pkg/oauth"
	"golang.org/x/oauth2"
)

// GetOAuthConf gets the oauth2 config object
func GetOAuthConf(oauthServerAuthURL *string, oauthServerTokenURL *string, apiServer *string, gatewayBaseAddress *string, oauthServerClientID *string, oauthServerClientSecret *string, transport *http.Transport) *oauth2.Config {
	var endpoint oauth.Endpoint
	var oauthConf *oauth2.Config
	var err error

	// Try to autodetect auth sever endpoints
	if *oauthServerAuthURL != "" && *oauthServerTokenURL != "" {
		endpoint.Token = *oauthServerTokenURL
		endpoint.Auth = *oauthServerAuthURL
	} else {
		endpoint, err = oauth.GetServerEndpoint(*apiServer, transport)
		if err != nil {
			LogErrorAndExit(err)
		}
		glog.Infof("auto detect oauth server endpoints from [%s]", *apiServer)
	}

	// Set oauth config
	redirectURL := fmt.Sprintf("%s%s", *gatewayBaseAddress, authLoginCallbackEndpoint)
	oauthConf = &oauth2.Config{
		ClientID:     *oauthServerClientID,
		ClientSecret: *oauthServerClientSecret,
		Scopes:       []string{"user:full"},
		Endpoint: oauth2.Endpoint{
			TokenURL: endpoint.Token,
			AuthURL:  endpoint.Auth,
		},
		RedirectURL: redirectURL,
	}

	glog.Infof("OAuth Token : [%s]", endpoint.Token)
	glog.Infof("OAuth Auth  : [%s]", endpoint.Auth)

	return oauthConf
}
