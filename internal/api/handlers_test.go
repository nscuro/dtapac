package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/nscuro/dtapac/internal/opa"
	"github.com/nscuro/dtapac/internal/policy/model"
)

func TestHandleNotification(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		auditChan := make(chan any, 2)
		srv := NewServer("", auditChan, nil, zerolog.Logger{})

		notificationFile, err := os.Open("./testdata/dtrack-new-vulnerability.json")
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = notificationFile.Close()
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/dtrack/notification", notificationFile)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		res := rec.Result()
		require.Equal(t, http.StatusAccepted, res.StatusCode)
		require.Len(t, auditChan, 2)

		auditItem := <-auditChan
		require.IsType(t, model.Finding{}, auditItem)
		finding := auditItem.(model.Finding)
		require.Equal(t, "4d5cd8df-cff7-4212-a038-91ae4ab79396", finding.Component.UUID.String())
		require.Equal(t, "6fb1820f-5280-4577-ac51-40124aabe307", finding.Project.UUID.String())
		require.Equal(t, "941a93f5-e06b-4304-84de-4d788eeb4969", finding.Vulnerability.UUID.String())

		auditItem = <-auditChan
		require.IsType(t, model.Finding{}, auditItem)
		finding = auditItem.(model.Finding)
		require.Equal(t, "4d5cd8df-cff7-4212-a038-91ae4ab79396", finding.Component.UUID.String())
		require.Equal(t, "09479a81-44b4-4223-bea7-de8697d47a6e", finding.Project.UUID.String())
		require.Equal(t, "941a93f5-e06b-4304-84de-4d788eeb4969", finding.Vulnerability.UUID.String())
	})
}

func TestHandleOPAStatus(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		statusChan := make(chan opa.Status, 1)
		srv := NewServer("", nil, statusChan, zerolog.Nop())

		statusFile, err := os.Open("./testdata/opa-status.json")
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = statusFile.Close()
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/opa/status", statusFile)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		res := rec.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.NotEmpty(t, statusChan)

		status := <-statusChan
		require.Len(t, status.Bundles, 1)
		require.Contains(t, status.Bundles, "http/example/authz")
	})

	t.Run("NoBody", func(t *testing.T) {
		statusChan := make(chan opa.Status, 1)
		srv := NewServer("", nil, statusChan, zerolog.Nop())

		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/opa/status", nil))

		res := rec.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
		require.Empty(t, statusChan)
	})
}
