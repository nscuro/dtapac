package audit

import (
	"context"
	"fmt"
	"path"

	"github.com/DependencyTrack/client-go"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/opa"
)

type Auditor interface {
	AuditFinding(ctx context.Context, finding Finding) (dtrack.AnalysisRequest, error)
	AuditViolation(ctx context.Context, violation Violation) (dtrack.ViolationAnalysisRequest, error)
}

type OPAAuditor struct {
	opaClient           *opa.Client
	findingPolicyPath   string
	violationPolicyPath string
	logger              zerolog.Logger
}

func NewOPAAuditor(opaClient *opa.Client, findingPolicyPath, violationPolicyPath string, logger zerolog.Logger) (*OPAAuditor, error) {
	if opaClient == nil {
		return nil, fmt.Errorf("no opa client provided")
	}
	if findingPolicyPath == "" && violationPolicyPath == "" {
		return nil, fmt.Errorf("no policy path provided, at least one is required")
	}

	return &OPAAuditor{
		opaClient:           opaClient,
		findingPolicyPath:   findingPolicyPath,
		violationPolicyPath: violationPolicyPath,
		logger:              logger,
	}, nil
}

func (a OPAAuditor) AuditFinding(ctx context.Context, finding Finding) (req dtrack.AnalysisRequest, err error) {
	if a.findingPolicyPath == "" {
		a.logger.Warn().
			Object("finding", finding).
			Msg("cannot audit finding because no policy path was configured")
		return
	}

	a.logger.Debug().Object("finding", finding).Msg("auditing finding")

	var analysis FindingAnalysis
	err = a.opaClient.Decision(ctx, path.Join(a.findingPolicyPath, "/analysis"), finding, &analysis)
	if err != nil {
		totalAudited.WithLabelValues(metricsLabelStatusFailed, metricsLabelTypeFinding).Inc()
		return
	}

	if analysis == (FindingAnalysis{}) {
		totalAudited.WithLabelValues(metricsLabelStatusUnmatched, metricsLabelTypeFinding).Inc()
		a.logger.Debug().Object("finding", finding).Msg("finding is not covered by policy")
		return
	}

	totalAudited.WithLabelValues(metricsLabelStatusSuccess, metricsLabelTypeFinding).Inc()
	a.logger.Debug().Object("analysis", analysis).Msg("received finding analysis")

	req = dtrack.AnalysisRequest{
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

	return
}

func (a OPAAuditor) AuditViolation(ctx context.Context, violation Violation) (req dtrack.ViolationAnalysisRequest, err error) {
	if a.findingPolicyPath == "" {
		a.logger.Warn().
			Object("violation", violation).
			Msg("cannot audit violation because no policy path was configured")
		return
	}

	a.logger.Debug().Object("violation", violation).Msg("auditing violation")

	var analysis ViolationAnalysis
	err = a.opaClient.Decision(ctx, path.Join(a.violationPolicyPath, "/analysis"), violation, &analysis)
	if err != nil {
		totalAudited.WithLabelValues(metricsLabelStatusFailed, metricsLabelTypeFinding).Inc()
		return
	}

	if analysis == (ViolationAnalysis{}) {
		totalAudited.WithLabelValues(metricsLabelStatusUnmatched, metricsLabelTypeViolation).Inc()
		a.logger.Debug().Object("violation", violation).Msg("violation is not covered by policy")
		return
	}

	totalAudited.WithLabelValues(metricsLabelStatusSuccess, metricsLabelTypeViolation).Inc()
	a.logger.Debug().Object("analysis", analysis).Msg("received violation analysis")

	req = dtrack.ViolationAnalysisRequest{
		Component:       violation.Component.UUID,
		PolicyViolation: violation.PolicyViolation.UUID,
		State:           analysis.State,
		Comment:         analysis.Comment,
		Suppressed:      analysis.Suppress,
	}

	return
}
