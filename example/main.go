// An example for Google OAuth 2.0 for TV and Limited-Input Device Applications,
// described in https://developers.google.com/identity/protocols/oauth2/limited-input-device
//
// To run this example,
//
//	go run ./example -client-id YOUR_ID -client-secret YOUR_SECRET
//
// You need to create an OAuth client before running this example.
// Open the Google Cloud console https://console.cloud.google.com/apis/credentials,
// create an OAuth client ID with "Limited Input devices",
// and then get the client ID and secret.
package main

import (
	"context"
	"flag"
	"log"
	"strings"

	"github.com/int128/oauth2dev"
	"golang.org/x/oauth2"
)

func main() {
	var cfg oauth2.Config
	var scopes string
	flag.StringVar(&cfg.Endpoint.AuthURL, "auth-url", "https://oauth2.googleapis.com/device/code", "Authorization endpoint")
	flag.StringVar(&cfg.Endpoint.TokenURL, "token-url", "https://oauth2.googleapis.com/token", "Token endpoint")
	flag.StringVar(&cfg.ClientID, "client-id", "", "OAuth Client ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", "", "OAuth Client Secret (optional)")
	flag.StringVar(&scopes, "scopes", "email", "Scopes to request, comma separated")
	flag.Parse()
	cfg.Scopes = strings.Split(scopes, ",")

	ctx := context.Background()
	token, err := oauth2dev.GetToken(ctx, cfg, func(ar oauth2dev.AuthorizationResponse) {
		log.Printf("Visit %s and enter the code: %s", ar.URL(), ar.UserCode)
	})
	if err != nil {
		log.Fatalf("unable to get token: %s", err)
	}

	log.Printf("You got a valid token until %s", token.Expiry)
}
