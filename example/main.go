// An example for Google OAuth 2.0 for TV and Limited-Input Device Applications,
// described in https://developers.google.com/identity/protocols/oauth2/limited-input-device
package main

import (
	"context"
	"log"
	"os"

	"github.com/int128/oauth2dev"
	"golang.org/x/oauth2"
)

func main() {
	cfg := oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://oauth2.googleapis.com/device/code",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		Scopes: []string{"email"},
	}

	ctx := context.Background()
	token, err := oauth2dev.GetToken(ctx, cfg, func(ar oauth2dev.AuthorizationResponse) {
		log.Printf("Visit %s and enter the code: %s", ar.URL(), ar.UserCode)
	})
	if err != nil {
		log.Fatalf("unable to get token: %s", err)
	}

	log.Printf("You got a valid token until %s", token.Expiry)
}
