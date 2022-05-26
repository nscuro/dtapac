package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nscuro/dtrack-client"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/model"
	"github.com/nscuro/dtapac/internal/opa"
)

func handleNotification(auditChan chan<- any, findingAuditor audit.FindingAuditor, violationAuditor audit.ViolationAuditor) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		logger := getRequestLogger(r)

		notification, err := dtrack.ParseNotification(r.Body)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse notification")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if notification.Group != "NEW_VULNERABILITY" && notification.Group != "POLICY_VIOLATION" {
			logger.Warn().Str("group", notification.Group).Msg("unsupported notification group")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		switch subject := notification.Subject.(type) {
		case *dtrack.NewVulnerabilitySubject:
			if findingAuditor == nil {
				logger.Warn().Msg("received new vulnerability notification, but findings auditing is disabled")
				break
			}

			for i := range subject.AffectedProjects {
				finding := model.Finding{
					Component:     subject.Component,
					Project:       subject.AffectedProjects[i],
					Vulnerability: subject.Vulnerability,
				}

				analysis, auditErr := findingAuditor(finding)
				if auditErr == nil {
					if analysis != (model.FindingAnalysis{}) {
						auditChan <- dtrack.AnalysisRequest{
							Component:     finding.Component.UUID,
							Project:       finding.Project.UUID,
							Vulnerability: finding.Vulnerability.UUID,
							State:         analysis.State,
							Justification: analysis.Justification,
							Response:      analysis.Response,
							Details:       analysis.Details,
							Comment:       analysis.Comment,
							Suppressed:    analysis.Suppress,
						}
					} else {
						logger.Debug().Object("finding", finding).Msg("finding is not covered by policy")
					}
				} else {
					logger.Error().Err(auditErr).Object("finding", finding).Msg("failed to audit finding")
				}
			}
		case *dtrack.PolicyViolationSubject:
			if violationAuditor == nil {
				logger.Warn().Msg("received policy violation notification, but violations auditing is disabled")
				break
			}

			violation := model.Violation{
				Component:       subject.Component,
				Project:         subject.Project,
				PolicyViolation: subject.PolicyViolation,
			}

			analysis, auditErr := violationAuditor(violation)
			if auditErr == nil {
				if analysis != (model.ViolationAnalysis{}) {
					auditChan <- dtrack.ViolationAnalysisRequest{
						Component:       subject.Component.UUID,
						PolicyViolation: subject.PolicyViolation.UUID,
						State:           analysis.State,
						Comment:         analysis.Comment,
						Suppressed:      analysis.Suppress,
					}
				} else {
					logger.Debug().Object("violation", violation).Msg("violation is not covered by policy")
				}
			} else {
				logger.Error().Err(auditErr).Object("violation", violation).Msg("failed to audit violation")
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

		select {
		case statusChan <- status:
		default:
			logger.Warn().Msg("received opa status update, but a previous update is still waiting to be processed")
		}

		rw.WriteHeader(http.StatusOK)
	}
}
