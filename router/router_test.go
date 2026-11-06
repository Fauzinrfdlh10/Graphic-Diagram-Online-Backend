package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/RenzIP/Graphic-Diagram-Online/config"
	"github.com/RenzIP/Graphic-Diagram-Online/handler"
)

func TestHealthEndpointIsPublic(t *testing.T) {
	app := fiber.New()
	Setup(app, &config.Config{
		FrontendURL: "http://localhost:3000",
		JWTSecret:   "test-secret",
	}, Handlers{
		Health: handler.NewHealthHandler(),
	})

	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if err != nil {
		t.Fatalf("request health endpoint: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health endpoint returned %d, want %d", response.StatusCode, http.StatusOK)
	}
}
