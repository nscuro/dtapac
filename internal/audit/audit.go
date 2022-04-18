package audit

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/model"
	"github.com/nscuro/dtapac/internal/policy"
)

// Auditor TODO
type Auditor struct {
	policyEvaler *policy.Evaluator[model.Finding, model.FindingAnalysis]
	dtrackClient *dtrack.Client
	logger       zerolog.Logger
}

func NewAuditor(
	policyEvaler *policy.Evaluator[model.Finding, model.FindingAnalysis],
	dtrackClient *dtrack.Client, logger zerolog.Logger) *Auditor {
	return &Auditor{
		policyEvaler: policyEvaler,
		dtrackClient: dtrackClient,
		logger:       logger,
	}
}

// AuditFinding TODO
func (a Auditor) AuditFinding(ctx context.Context, finding model.Finding) (err error) {
	findingLogger := a.logger.With().Object("finding", finding).Logger()

	analysis, err := a.policyEvaler.Eval(ctx, finding)
	if err != nil {
		return
	} else if analysis == (model.FindingAnalysis{}) {
		findingLogger.Debug().Msg("not covered by policy")
		return
	}

	findingLogger.Debug().Msg("fetching existing analysis")
	exAnalysis, err := a.dtrackClient.Analysis.Get(ctx, finding.Component.UUID, finding.Project.UUID, finding.Vulnerability.UUID)
	if err != nil {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
		if errors.Is(err, io.EOF) {
			findingLogger.Debug().Msg("no analysis exists yet")
		} else {
			err = fmt.Errorf("failed to fetch existing analysis: %w", err)
			return
		}
	}

	analysisReq := dtrack.AnalysisRequest{
		Component:     finding.Component.UUID,
		Project:       finding.Project.UUID,
		Vulnerability: finding.Vulnerability.UUID,
		State:         analysis.State,
		Justification: analysis.Justification,
		Response:      analysis.Response,
		Suppressed:    analysis.Suppress,
	}

	// Check whether the analysis is already in the desired state.
	// If it is, there's no need for us to submit another request.
	if exAnalysis != nil {
		if analysis.State != exAnalysis.State {
			analysisReq.State = analysis.State
		}
		if analysis.Justification != "" && analysis.Justification != exAnalysis.Justification {
			analysisReq.Justification = analysis.Justification
		}
		if analysis.Response != "" && analysis.Response != exAnalysis.Response {
			analysisReq.Response = analysis.Response
		}
		if analysis.Comment != "" {
			var commentExists bool
			for _, comment := range exAnalysis.Comments {
				if comment.Comment == analysis.Comment {
					commentExists = true
					break
				}
			}
			if !commentExists {
				analysisReq.Comment = analysis.Comment
			}
		}
		if analysis.Suppress != nil && *analysis.Suppress != exAnalysis.Suppressed {
			analysisReq.Suppressed = analysis.Suppress
		}
	}

	// Note: Use a context that is decoupled from ctx here!
	// We don't want in-flight requests to be canceled.
	findingLogger.Debug().Interface("analysis", analysisReq).Msg("submitting analysis")
	_, err = a.dtrackClient.Analysis.Create(context.Background(), analysisReq)
	if err != nil {
		err = fmt.Errorf("failed to create analysis: %w", err)
		return
	}

	return nil
}
