package audit

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/moby/locker"
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/policy"
	"github.com/nscuro/dtapac/internal/policy/model"
)

type dtrackAnalysisSvc interface {
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*dtrack.Analysis, error)
	Create(context.Context, dtrack.AnalysisRequest) (*dtrack.Analysis, error)
}

// Auditor TODO
type Auditor struct {
	findingPolicyEvaler   policy.Evaluator
	violationPolicyEvaler policy.Evaluator
	analysisSvc           dtrackAnalysisSvc
	findingLocker         *locker.Locker
	violationLocker       *locker.Locker
	logger                zerolog.Logger
}

// NewAuditor TODO
func NewAuditor(findingPolicyEvaler, violationPolicyEvaler policy.Evaluator, analysisSvc dtrackAnalysisSvc, logger zerolog.Logger) *Auditor {
	return &Auditor{
		findingPolicyEvaler:   findingPolicyEvaler,
		violationPolicyEvaler: violationPolicyEvaler,
		analysisSvc:           analysisSvc,
		findingLocker:         locker.New(),
		violationLocker:       locker.New(),
		logger:                logger,
	}
}

// Audit TODO
func (a *Auditor) Audit(ctx context.Context, auditChan <-chan any) error {
	var (
		auditItem   any
		channelOpen bool
		err         error
	)

	for {
		select {
		case auditItem, channelOpen = <-auditChan:
			if !channelOpen {
				a.logger.Debug().Str("reason", "channel closed").Msg("stopping")
				return nil
			}
			break
		case <-ctx.Done():
			a.logger.Debug().Str("reason", "canceled").Msg("stopping")
			return ctx.Err()
		}

		switch item := auditItem.(type) {
		case model.Finding:
			err = a.auditFinding(ctx, item)
		case model.Violation:
			err = a.auditViolation(ctx, item)
		default:
			err = fmt.Errorf("cannot audit item of type %T", auditItem)
		}
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to audit item")
		}
	}
}

func (a *Auditor) auditFinding(ctx context.Context, finding model.Finding) (err error) {
	findingLogger := a.logger.With().Object("finding", finding).Logger()

	var analysis model.FindingAnalysis
	err = a.findingPolicyEvaler.Eval(ctx, finding, &analysis)
	if err != nil {
		return
	} else if analysis == (model.FindingAnalysis{}) {
		findingLogger.Debug().Msg("not covered by policy")
		return
	}

	// It can happen that the same finding is audited concurrently, so we need a way to
	// prevent dirty reads and redundant writes.
	lockName := fmt.Sprintf("%s:%s:%s", finding.Component.UUID, finding.Project.UUID, finding.Vulnerability.UUID)
	a.findingLocker.Lock(lockName)
	defer func() {
		err := a.findingLocker.Unlock(lockName)
		if err != nil {
			a.logger.Error().Err(err).
				Str("lock", lockName).
				Msg("failed to unlock")
		}
	}()

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

	analysisReq := buildAnalysisRequest(analysis, existingAnalysis)

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

func (a *Auditor) auditViolation(_ context.Context, _ model.Violation) error {
	// TODO
	return nil
}

func buildAnalysisRequest(analysis model.FindingAnalysis, existing *dtrack.Analysis) dtrack.AnalysisRequest {
	req := dtrack.AnalysisRequest{
		State:         analysis.State,
		Justification: analysis.Justification,
		Response:      analysis.Response,
		Comment:       analysis.Comment,
		Suppressed:    analysis.Suppress,
	}

	if existing != nil {
		// Apply statuses of the existing analysis if the policy
		// analysis doesn't set them already. If we don't do this,
		// we'll be overriding them to NOT_SET in Dependency-Track.
		if req.State == "" && existing.State != "" {
			req.State = existing.State
		}
		if req.Justification == "" && existing.Justification != "" {
			req.Justification = existing.Justification
		}
		if req.Response == "" && existing.Response != "" {
			req.Response = existing.Response
		}

		// Prevent redundant comments.
		if req.Comment != "" {
			commentExists := false
			for _, comment := range existing.Comments {
				if comment.Comment == req.Comment {
					commentExists = true
					break
				}
			}
			if commentExists {
				req.Comment = ""
			}
		}

		// Let's see... did anything change at all?
		if req.State == existing.State &&
			req.Justification == existing.Justification &&
			req.Response == existing.Response &&
			req.Comment == "" &&
			(req.Suppressed == nil || *req.Suppressed == existing.Suppressed) {
			// Nope. Same old same old.
			return dtrack.AnalysisRequest{}
		}
	}

	return req
}
