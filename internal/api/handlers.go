package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/DependencyTrack/client-go/notification"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

func handleDTNotification(dtClient *dtrack.Client, auditChan chan<- any, auditor audit.Auditor) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		logger := getRequestLogger(r)

		n, err := notification.Parse(r.Body)
		if err != nil {
			logger.Error().Err(err).Msg("failed to parse notification")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		switch subject := n.Subject.(type) {
		case *notification.NewVulnerabilitySubject:
			logger.Info().Str("content", n.Content).Msg("Received notification")
			go handleVulnerability(*subject, dtClient, auditChan, auditor, logger)

		case *notification.PolicyViolationSubject:
			violation := audit.Violation{
				Component:       resolveComponent(subject.Component, dtClient, logger),
				Project:         resolveProject(subject.Project, dtClient, logger),
				PolicyViolation: mapPolicyViolation(subject.PolicyViolation),
			}

			violationAnalysisReq, auditErr := auditor.AuditViolation(context.Background(), violation)
			if auditErr == nil && violationAnalysisReq != (dtrack.ViolationAnalysisRequest{}) {
				auditChan <- violationAnalysisReq
			} else if auditErr != nil {
				logger.Error().Err(auditErr).Object("violation", violation).Msg("failed to audit violation")
			}
		default:
			logger.Error().
				Str("group", n.Group).
				Str("subjectType", fmt.Sprintf("%T", n.Subject)).
				Msg("notification subject is of unexpected type")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		rw.WriteHeader(http.StatusAccepted)
	}
}

var lock sync.Mutex

func handleVulnerability(subject notification.NewVulnerabilitySubject, dtClient *dtrack.Client, auditChan chan<- any, auditor audit.Auditor, logger zerolog.Logger) {
	lock.Lock()

	component := resolveComponent(subject.Component, dtClient, logger)

	logger.Info().Str("component", component.UUID.String()).Msg("Handling notification started")

	project := resolveProjectFromComponent(*component.Project, dtClient, logger)

	finding := audit.Finding{
		Component:     component,
		Project:       project,
		Vulnerability: resolveVulnerability(subject.Vulnerability, dtClient, logger),
	}

	analysisReq, auditErr := auditor.AuditFinding(context.Background(), finding)
	if auditErr == nil && analysisReq != (dtrack.AnalysisRequest{}) {
		auditChan <- analysisReq
	} else if auditErr != nil {
		logger.Error().Err(auditErr).Object("finding", finding).Msg("failed to audit finding")
	}
	logger.Info().Str("component", component.UUID.String()).Msg("Handling notification done")
	
	lock.Unlock()
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

func resolveComponent(input notification.Component, dtClient *dtrack.Client, logger zerolog.Logger) (component dtrack.Component) {
	component, err := dtClient.Component.Get(context.Background(), input.UUID)
	if err != nil {
		logger.Warn().Err(err).
			Str("component", input.UUID.String()).
			Msg("failed to fetch component, proceeding with component from notification instead")
		component = mapComponent(input)
	}

	return
}

func resolveProjectFromComponent(input dtrack.Project, dtClient *dtrack.Client, logger zerolog.Logger) (project dtrack.Project) {
	project, err := dtClient.Project.Get(context.Background(), input.UUID)
	if err != nil {
		logger.Error().Err(err).
			Str("project", input.UUID.String()).
			Msg("failed to fetch project, proceeding with project from component instead")
			project = input
	}

	return
}

func resolveProject(input notification.Project, dtClient *dtrack.Client, logger zerolog.Logger) (project dtrack.Project) {
	project, err := dtClient.Project.Get(context.Background(), input.UUID)
	if err != nil {
		logger.Error().Err(err).
			Str("project", input.UUID.String()).
			Msg("failed to fetch project, proceeding with project from notification instead")
		project = mapProject(input)
	}

	return
}

func resolveVulnerability(input notification.Vulnerability, dtClient *dtrack.Client, logger zerolog.Logger) (vuln dtrack.Vulnerability) {
	vuln, err := dtClient.Vulnerability.Get(context.Background(), input.UUID)
	if err != nil {
		logger.Error().Err(err).
			Str("vulnerability", input.UUID.String()).
			Msg("failed to fetch vulnerability, proceeding with vulnerability from notification instead")
		vuln = mapVulnerability(input)
	}

	return
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
			Subject:  dtrack.PolicyConditionSubject(input.PolicyCondition.Subject),
			Operator: dtrack.PolicyConditionOperator(input.PolicyCondition.Operator),
			Value:    input.PolicyCondition.Value,
			Policy: &dtrack.Policy{
				UUID:           input.PolicyCondition.Policy.UUID,
				Name:           input.PolicyCondition.Policy.Name,
				ViolationState: dtrack.PolicyViolationState(input.PolicyCondition.Policy.ViolationState),
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
