package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nscuro/dtrack-client"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/model"
	"github.com/nscuro/dtapac/internal/opa"
)

func handleNotification(auditChan chan<- any, findingAuditor audit.FindingAuditor) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		logger := getRequestLogger(r)

		bodyContent, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error().Err(err).Msg("failed to read request body")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		notification, err := dtrack.ParseNotification(bodyContent)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse notification")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if notification.Group != "NEW_VULNERABILITY" {
			logger.Warn().Str("group", notification.Group).Msg("unsupported notification group")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		switch subject := notification.Subject.(type) {
		case *dtrack.NewVulnerabilitySubject:
			for i := range subject.AffectedProjects {
				finding := model.Finding{
					Component:     subject.Component,
					Project:       subject.AffectedProjects[i],
					Vulnerability: subject.Vulnerability,
				}

				analysis, err := findingAuditor(finding)
				if err == nil {
					if analysis != (model.FindingAnalysis{}) {
						auditChan <- dtrack.AnalysisRequest{
							Component:     finding.Component.UUID,
							Project:       finding.Project.UUID,
							Vulnerability: finding.Vulnerability.UUID,
							State:         analysis.State,
							Justification: analysis.Justification,
							Response:      analysis.Response,
							Comment:       analysis.Comment,
							Suppressed:    analysis.Suppress,
						}
					} else {
						logger.Debug().Object("finding", finding).Msg("finding is not covered by policy")
					}
				} else {
					logger.Error().Err(err).Object("finding", finding).Msg("failed to audit finding")
				}
			}
		default:
			// The only way this can ever happen is when dtrack-client
			// has a bug in its notification parsing logic.
			logger.Error().
				Str("type", fmt.Sprintf("%T", notification.Subject)).
				Msg("notification subject is of unexpected type")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		rw.WriteHeader(http.StatusAccepted)
	}
}

func handleOPAStatus(statusChan chan<- opa.Status) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		logger := getRequestLogger(r)

		var status opa.Status
		err := json.NewDecoder(r.Body).Decode(&status)
		if err != nil {
			logger.Error().Err(err).Msg("failed to decode request body")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		statusChan <- status

		rw.WriteHeader(http.StatusOK)
	}
}