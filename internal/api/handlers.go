package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nscuro/dtrack-client"
	"github.com/nscuro/dtrack-client/notification"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

func handleNotification(auditChan chan<- any, auditor audit.Auditor) http.HandlerFunc {
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
			for i := range subject.AffectedProjects {
				finding := audit.Finding{
					Component:     mapComponent(subject.Component),
					Project:       mapProject(subject.AffectedProjects[i]),
					Vulnerability: mapVulnerability(subject.Vulnerability),
				}

				analysisReq, auditErr := auditor.AuditFinding(context.Background(), finding)
				if auditErr == nil && analysisReq != (dtrack.AnalysisRequest{}) {
					auditChan <- analysisReq
				} else if auditErr != nil {
					logger.Error().Err(auditErr).Object("finding", finding).Msg("failed to audit finding")
				}
			}
		case *notification.PolicyViolationSubject:
			violation := audit.Violation{
				Component:       mapComponent(subject.Component),
				Project:         mapProject(subject.Project),
				PolicyViolation: mapPolicyViolation(subject.PolicyViolation),
			}

			analysisReq, auditErr := auditor.AuditViolation(context.Background(), violation)
			if auditErr == nil && analysisReq != (dtrack.ViolationAnalysisRequest{}) {
				auditChan <- analysisReq
			} else if auditErr != nil {
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
