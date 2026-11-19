package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/RenzIP/Graphic-Diagram-Online/config"
)

func TestOAuthLoginRedirects(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		provider    string
		clientID    string
		authURL     string
		redirectURI string
	}{
		{
			name:        "Google",
			path:        "/google",
			provider:    "google",
			clientID:    "google-client",
			authURL:     "https://accounts.google.com/o/oauth2/v2/auth",
			redirectURI: "https://api.example.test/base/api/auth/google/callback",
		},
		{
			name:        "GitHub",
			path:        "/github",
			provider:    "github",
			clientID:    "github-client",
			authURL:     "https://github.com/login/oauth/authorize",
			redirectURI: "https://api.example.test/base/api/auth/github/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				FrontendURL:        "https://app.example.test/",
				BackendURL:         "https://api.example.test/base/",
				GoogleClientID:     tt.clientID,
				GoogleClientSecret: "client-secret",
				GitHubClientID:     tt.clientID,
				GitHubClientSecret: "client-secret",
			}
			handler := NewAuthHandler(nil, cfg)
			app := fiber.New()
			if tt.provider == "google" {
				app.Get(tt.path, handler.GoogleLogin)
			} else {
				app.Get(tt.path, handler.GitHubLogin)
			}

			resp, err := app.Test(httptest.NewRequest(http.MethodGet, tt.path, nil))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != fiber.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusTemporaryRedirect)
			}

			location, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("invalid redirect URL: %v", err)
			}
			if location.Scheme+"://"+location.Host+location.Path != tt.authURL {
				t.Fatalf("redirect host/path = %q, want %q", location.Scheme+"://"+location.Host+location.Path, tt.authURL)
			}
			if got := location.Query().Get("client_id"); got != tt.clientID {
				t.Errorf("client_id = %q, want %q", got, tt.clientID)
			}
			if got := location.Query().Get("redirect_uri"); got != tt.redirectURI {
				t.Errorf("redirect_uri = %q, want %q", got, tt.redirectURI)
			}
			if got := location.Query().Get("state"); got == "" {
				t.Error("state is empty")
			}
		})
	}
}

func TestOAuthLoginReportsMissingProviderCredentials(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		provider  string
		wantError string
	}{
		{name: "Google", path: "/google", provider: "google", wantError: "google_not_configured"},
		{name: "GitHub", path: "/github", provider: "github", wantError: "github_not_configured"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(nil, &config.Config{FrontendURL: "http://localhost:3000/"})
			app := fiber.New()
			if tt.provider == "google" {
				app.Get(tt.path, handler.GoogleLogin)
			} else {
				app.Get(tt.path, handler.GitHubLogin)
			}

			resp, err := app.Test(httptest.NewRequest(http.MethodGet, tt.path, nil))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != fiber.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusTemporaryRedirect)
			}
			if got, want := resp.Header.Get("Location"), "http://localhost:3000/login?error="+tt.wantError; got != want {
				t.Errorf("location = %q, want %q", got, want)
			}
		})
	}
}
