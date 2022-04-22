package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/nscuro/dtapac/internal/model"
)

func TestHandleNotification(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		auditChan := make(chan any, 2)
		srv := NewServer("", auditChan, zerolog.Logger{})

		notificationFile, err := os.Open("./testdata/dtrack-new-vuln.json")
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
