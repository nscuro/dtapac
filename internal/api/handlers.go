package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nscuro/dtrack-client"
	"github.com/nscuro/dtrack-client/notification"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

func handleNotification(auditChan chan<- any, findingAuditor audit.FindingAuditor, violationAuditor audit.ViolationAuditor) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		logger := getRequestLogger(r)

		n, err := notification.Parse(r.Body)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse notification")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if n.Group != notification.GroupNewVulnerability && n.Group != notification.GroupPolicyViolation {
			logger.Warn().Str("group", n.Group).Msg("unsupported notification group")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		switch subject := n.Subject.(type) {
		case *notification.NewVulnerabilitySubject:
			if findingAuditor == nil {
				logger.Warn().Msg("received new vulnerability notification, but findings auditing is disabled")
				break
			}

			for i := range subject.AffectedProjects {
				finding := audit.Finding{
					Component:     mapComponent(subject.Component),
					Project:       mapProject(subject.AffectedProjects[i]),
					Vulnerability: mapVulnerability(subject.Vulnerability),
				}

				logger.Debug().Object("finding", finding).Msg("auditing finding")
				analysis, auditErr := findingAuditor(finding)
				if auditErr == nil {
					if analysis != (audit.FindingAnalysis{}) {
						logger.Debug().Object("analysis", analysis).Msg("received finding analysis")

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
		case *notification.PolicyViolationSubject:
			if violationAuditor == nil {
				logger.Warn().Msg("received policy violation notification, but violations auditing is disabled")
				break
			}

			violation := audit.Violation{
				Component:       mapComponent(subject.Component),
				Project:         mapProject(subject.Project),
				PolicyViolation: mapPolicyViolation(subject.PolicyViolation),
			}

			logger.Debug().Object("violation", violation).Msg("auditing violation")
			analysis, auditErr := violationAuditor(violation)
			if auditErr == nil {
				if analysis != (audit.ViolationAnalysis{}) {
					logger.Debug().Object("analysis", analysis).Msg("received violation analysis")

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
				Str("type", fmt.Sprintf("%T", n.Subject)).
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

func mapComponent(input notification.Component) dtrack.Component {
	return dtrack.Component{
		UUID:    input.UUID,
		Group:   input.Group,
		Name:    input.Name,
		Version: input.Version,
		MD5:     input.MD5,
		SHA1:    input.SHA1,
		SHA256:  input.SHA256,
		SHA512:  input.SHA512,
		PURL:    input.PURL,
	}
}

func mapPolicyViolation(input notification.PolicyViolation) dtrack.PolicyViolation {
	return dtrack.PolicyViolation{
		UUID: input.UUID,
		Type: input.Type,
		PolicyCondition: &dtrack.PolicyCondition{
			UUID:     input.PolicyCondition.UUID,
			Subject:  input.PolicyCondition.Subject,
			Operator: input.PolicyCondition.Operator,
			Value:    input.PolicyCondition.Value,
			Policy: &dtrack.Policy{
				UUID:           input.PolicyCondition.Policy.UUID,
				Name:           input.PolicyCondition.Policy.Name,
				ViolationState: input.PolicyCondition.Policy.ViolationState,
			},
		},
	}
}

func mapProject(input notification.Project) dtrack.Project {
	var projectTags []dtrack.Tag
	if len(input.Tags) > 0 {
		for _, tagName := range strings.Split(input.Tags, ",") {
			tagName = strings.TrimSpace(tagName)
			if tagName != "" {
				projectTags = append(projectTags, dtrack.Tag{Name: tagName})
			}
		}
	}

	return dtrack.Project{
		UUID:    input.UUID,
		Name:    input.Name,
		Version: input.Description,
		PURL:    input.PURL,
		Tags:    projectTags,
	}
}

func mapVulnerability(input notification.Vulnerability) dtrack.Vulnerability {
	return dtrack.Vulnerability{
		UUID:            input.UUID,
		VulnID:          input.VulnID,
		Source:          input.Source,
		Title:           input.Title,
		SubTitle:        input.SubTitle,
		Description:     input.Description,
		Recommendation:  input.Recommendation,
		CVSSV2BaseScore: input.CVSSV2,
		CVSSV3BaseScore: input.CVSSV3,
	}
}
