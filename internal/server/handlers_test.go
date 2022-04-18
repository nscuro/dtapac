package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/nscuro/dtapac/internal/model"
)

func TestFindingHandler_ServeHTTP(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		findingsChan := make(chan model.Finding, 2)
		t.Cleanup(func() {
			close(findingsChan)
		})

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`
{
    "notification": {
        "group": "NEW_VULNERABILITY",
        "subject": {
            "component": {
                "name": "acme-lib"
            },
            "vulnerability": {
                "vulnId": "CVE-2022-666"
            },
            "affectedProjects": [
                {
                    "name": "acme-project-a"
                },
                {
                    "name": "acme-project-b"
                }
            ]
        }
    }
}
		`))

		rw := httptest.NewRecorder()
		NewFindingHandler(findingsChan, zerolog.Nop()).ServeHTTP(rw, r)

		res := rw.Result()
		require.Equal(t, http.StatusAccepted, res.StatusCode)
		require.Equal(t, 2, len(findingsChan))

		finding := <-findingsChan
		require.Equal(t, "acme-lib", finding.Component.Name)
		require.Equal(t, "CVE-2022-666", finding.Vulnerability.VulnID)
		require.Equal(t, "acme-project-a", finding.Project.Name)

		finding = <-findingsChan
		require.Equal(t, "acme-lib", finding.Component.Name)
		require.Equal(t, "CVE-2022-666", finding.Vulnerability.VulnID)
		require.Equal(t, "acme-project-b", finding.Project.Name)
	})

	t.Run("NoBody", func(t *testing.T) {
		findingsChan := make(chan model.Finding, 1)
		t.Cleanup(func() {
			close(findingsChan)
		})

		r := httptest.NewRequest(http.MethodPost, "/", nil)
		rw := httptest.NewRecorder()
		NewFindingHandler(findingsChan, zerolog.Nop()).ServeHTTP(rw, r)

		res := rw.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
		require.Equal(t, 0, len(findingsChan))
	})

	t.Run("UnsupportedGroup", func(t *testing.T) {
		findingsChan := make(chan model.Finding, 1)
		t.Cleanup(func() {
			close(findingsChan)
		})

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`
			{"notification": {"group":"BOM_UPLOADED"}}
		`))

		rw := httptest.NewRecorder()
		NewFindingHandler(findingsChan, zerolog.Nop()).ServeHTTP(rw, r)

		res := rw.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
		require.Equal(t, 0, len(findingsChan))
	})
}
