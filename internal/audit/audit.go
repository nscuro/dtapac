package audit

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/model"
	"github.com/nscuro/dtapac/internal/policy"
)

// Auditor TODO
type Auditor struct {
	policyEvaler policy.Evaluator
	analysisSvc  dtrackAnalysisSvc
	logger       zerolog.Logger
}

// NewAuditor TODO
func NewAuditor(policyEvaler policy.Evaluator, analysisSvc dtrackAnalysisSvc, logger zerolog.Logger) *Auditor {
	return &Auditor{
		policyEvaler: policyEvaler,
		analysisSvc:  analysisSvc,
		logger:       logger,
	}
}

// AuditFinding TODO
func (a Auditor) AuditFinding(ctx context.Context, finding model.Finding) (err error) {
	findingLogger := a.logger.With().Object("finding", finding).Logger()

	var analysis model.FindingAnalysis
	err = a.policyEvaler.Eval(ctx, finding, &analysis)
	if err != nil {
		return
	} else if analysis == (model.FindingAnalysis{}) {
		findingLogger.Debug().Msg("not covered by policy")
		return
	}

	// TODO: Use a named mutex to lock the component:project:vulnerability combination.
	// It can happen that the same finding is audited concurrently, so we need a way to
	// prevent dirty reads and redundant writes.

	findingLogger.Debug().Msg("fetching existing analysis")
	existingAnalysis, err := a.analysisSvc.Get(ctx, finding.Component.UUID, finding.Project.UUID, finding.Vulnerability.UUID)
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

	analysisReq := a.buildAnalysisRequest(analysis, existingAnalysis)

	// Check whether the analysis is already in the desired state.
	// If it is, there's no need for us to submit another request.
	if analysisReq == (dtrack.AnalysisRequest{}) {
		findingLogger.Debug().Msg("analysis is still current")
		return
	} else {
		analysisReq.Component = finding.Component.UUID
		analysisReq.Project = finding.Project.UUID
		analysisReq.Vulnerability = finding.Vulnerability.UUID
	}

	// Note: Use a context that is decoupled from ctx here!
	// We don't want in-flight requests to be canceled.
	findingLogger.Debug().Interface("analysis", analysisReq).Msg("submitting analysis")
	_, err = a.analysisSvc.Create(context.Background(), analysisReq)
	if err != nil {
		err = fmt.Errorf("failed to create analysis: %w", err)
		return
	}

	return nil
}

func (a Auditor) buildAnalysisRequest(new model.FindingAnalysis, existing *dtrack.Analysis) (req dtrack.AnalysisRequest) {
	if existing != nil {
		if new.State != existing.State {
			req.State = new.State
		}
		if new.Justification != "" && new.Justification != existing.Justification {
			req.Justification = new.Justification
		}
		if new.Response != "" && new.Response != existing.Response {
			req.Response = new.Response
		}
		if new.Comment != "" {
			var commentExists bool
			for _, comment := range existing.Comments {
				if comment.Comment == new.Comment {
					commentExists = true
					break
				}
			}
			if !commentExists {
				req.Comment = new.Comment
			}
		}
		if new.Suppress != nil && *new.Suppress != existing.Suppressed {
			req.Suppressed = new.Suppress
		}
	} else {
		req = dtrack.AnalysisRequest{
			State:         new.State,
			Justification: new.Justification,
			Response:      new.Response,
			Comment:       new.Comment,
			Suppressed:    new.Suppress,
		}
	}

	return
}

type dtrackAnalysisSvc interface {
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*dtrack.Analysis, error)
	Create(context.Context, dtrack.AnalysisRequest) (*dtrack.Analysis, error)
}
