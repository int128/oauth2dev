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

func TestAuthorize(t *testing.T) {
	t.Run("success authorization response", func(t *testing.T) {
		m := http.NewServeMux()
		m.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
			// Device Authorization Request
			// https://www.rfc-editor.org/rfc/rfc8628#section-3.1
			if r.Method != "POST" {
				t.Errorf("method wants %s but was %s", "POST", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form error: %s", err)
			}
			want := url.Values{"client_id": {"oauth2dev-client-id"}}
			if diff := cmp.Diff(want, r.PostForm); diff != "" {
				t.Errorf("form mismatch (-want +got):\n%s", diff)
			}

			// Device Authorization Response
			// https://www.rfc-editor.org/rfc/rfc8628#section-3.1
			w.Header().Set("Content-Type", "application/json")
			_, err := io.WriteString(w, `{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://example.com/device",
  "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}`)
			if err != nil {
				t.Errorf("http write error: %s", err)
			}
		})
		sv := httptest.NewServer(m)
		defer sv.Close()

		cfg := oauth2.Config{
			ClientID: "oauth2dev-client-id",
			Endpoint: oauth2.Endpoint{
				AuthURL:  sv.URL + "/auth",
				TokenURL: sv.URL + "/token",
			},
		}
		got, err := Authorize(context.TODO(), cfg)
		if err != nil {
			t.Fatalf("authorize error: %s", err)
		}
		want := &AuthorizationResponse{
			DeviceCode:              "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
			UserCode:                "WDJB-MJHT",
			VerificationURI:         "https://example.com/device",
			VerificationURIComplete: "https://example.com/device?user_code=WDJB-MJHT",
			ExpiresIn:               1800,
			Interval:                5,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("authorization response mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("error response", func(t *testing.T) {
		m := http.NewServeMux()
		m.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
			// Error Response
			// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(400)
			_, err := io.WriteString(w, `{
  "error":"invalid_request"
}`)
			if err != nil {
				t.Errorf("http write error: %s", err)
			}
		})
		sv := httptest.NewServer(m)
		defer sv.Close()

		cfg := oauth2.Config{
			ClientID: "oauth2dev-client-id",
			Endpoint: oauth2.Endpoint{
				AuthURL:  sv.URL + "/auth",
				TokenURL: sv.URL + "/token",
			},
		}
		_, err := Authorize(context.TODO(), cfg)
		if err == nil {
			t.Fatalf("authorize error: %s", err)
		}
		var eresp AuthorizationErrorResponse
		if !errors.As(err, &eresp) {
			t.Fatalf("error is not AuthorizationErrorResponse: %s", err)
		}
		want := AuthorizationErrorResponse{
			StatusCode: 400,
			ErrorCode:  "invalid_request",
		}
		if diff := cmp.Diff(want, eresp); diff != "" {
			t.Errorf("error response mismatch (-want +got):\n%s", diff)
		}
	})
}
