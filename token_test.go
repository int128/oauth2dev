package oauth2dev

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
)

func TestPostTokenRequest(t *testing.T) {
	t.Run("successful response", func(t *testing.T) {
		m := http.NewServeMux()
		m.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("method wants %s but was %s", "POST", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form error: %s", err)
			}
			// the example request in https://www.rfc-editor.org/rfc/rfc8628#section-3.4,
			// with client_secret
			want, err := url.ParseQuery(
				"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" +
					"&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS" +
					"&client_id=1406020730" +
					"&client_secret=oauth2dev-client-secret",
			)
			if err != nil {
				t.Fatalf("invalid fixture query: %s", err)
			}
			if diff := cmp.Diff(want, r.PostForm); diff != "" {
				t.Errorf("form mismatch (-want +got):\n%s", diff)
			}

			// the example response in https://www.rfc-editor.org/rfc/rfc6749#section-5.1
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			_, err = io.WriteString(w, `{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter":"example_value"
}`)
			if err != nil {
				t.Errorf("http write error: %s", err)
			}
		})
		sv := httptest.NewServer(m)
		defer sv.Close()

		cfg := oauth2.Config{
			ClientID:     "1406020730",
			ClientSecret: "oauth2dev-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  sv.URL + "/auth",
				TokenURL: sv.URL + "/token",
			},
		}
		const deviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
		got, err := PostTokenRequest(context.TODO(), cfg, deviceCode)
		if err != nil {
			t.Fatalf("authorize error: %s", err)
		}
		want := &TokenResponse{
			AccessToken:  "2YotnFZFEjr1zCsicMWpAA",
			TokenType:    "example",
			RefreshToken: "tGzv3JOkF0XG5Qx2TlKWIA",
			ExpiresIn:    3600,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("token response mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("error response", func(t *testing.T) {
		m := http.NewServeMux()
		m.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form error: %s", err)
			}
			if r.PostForm.Has("client_secret") {
				t.Errorf("request should not have client_secret key but had it with value %s", r.PostForm.Get("client_secret"))
			}

			// the example response in https://www.rfc-editor.org/rfc/rfc6749#section-5.2
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(401)
			_, err := io.WriteString(w, `{
  "error":"invalid_client"
}`)
			if err != nil {
				t.Errorf("http write error: %s", err)
			}
		})
		sv := httptest.NewServer(m)
		defer sv.Close()

		cfg := oauth2.Config{
			ClientID: "oauth2dev-client-id",
			// omit ClientSecret
			Endpoint: oauth2.Endpoint{
				AuthURL:  sv.URL + "/auth",
				TokenURL: sv.URL + "/token",
			},
		}
		_, err := PostTokenRequest(context.TODO(), cfg, "oauth2dev-device-code")
		if err == nil {
			t.Fatalf("token error was nil")
		}
		var eresp TokenErrorResponse
		if !errors.As(err, &eresp) {
			t.Fatalf("error is not TokenErrorResponse: %s", err)
		}
		want := TokenErrorResponse{
			StatusCode: 401,
			ErrorCode:  "invalid_client",
		}
		if diff := cmp.Diff(want, eresp); diff != "" {
			t.Errorf("error response mismatch (-want +got):\n%s", diff)
		}
	})
}
