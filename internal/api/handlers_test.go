package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/nscuro/dtapac/internal/audit"
)

func TestHandleNotification(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		var findingAuditor audit.FindingAuditor = func(finding audit.Finding) (audit.FindingAnalysis, error) {
			if finding.Project.UUID.String() == "6fb1820f-5280-4577-ac51-40124aabe307" {
				return audit.FindingAnalysis{
					Comment: "Foobar",
				}, nil
			} else {
				return audit.FindingAnalysis{}, nil
			}
		}
		srv := NewServer("", findingAuditor, nil, zerolog.Logger{})

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
		require.Len(t, srv.AuditResultChan(), 1)

		auditItem := <-srv.AuditResultChan()
		require.IsType(t, dtrack.AnalysisRequest{}, auditItem)
		analysisReq := auditItem.(dtrack.AnalysisRequest)
		require.Equal(t, "4d5cd8df-cff7-4212-a038-91ae4ab79396", analysisReq.Component.String())
		require.Equal(t, "6fb1820f-5280-4577-ac51-40124aabe307", analysisReq.Project.String())
		require.Equal(t, "941a93f5-e06b-4304-84de-4d788eeb4969", analysisReq.Vulnerability.String())
		require.Equal(t, "", string(analysisReq.State))
		require.Equal(t, "", string(analysisReq.Justification))
		require.Equal(t, "", string(analysisReq.Response))
		require.Equal(t, "Foobar", analysisReq.Comment)
		require.Nil(t, analysisReq.Suppressed)
	})
}
