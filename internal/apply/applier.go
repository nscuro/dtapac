package apply

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"
)

// Applier applies desired analysis states to a Dependency-Track instance.
type Applier struct {
	analysisSvc          analysisService
	violationAnalysisSvc violationAnalysisService
	logger               zerolog.Logger
	dryRun               bool
}

func NewApplier(analysisSvc analysisService, violationAnalysisSvc violationAnalysisService, logger zerolog.Logger) *Applier {
	return &Applier{
		analysisSvc:          analysisSvc,
		violationAnalysisSvc: violationAnalysisSvc,
		logger:               logger,
	}
}

func (a *Applier) Start(ctx context.Context, auditResultChan <-chan interface{}) error {
	a.logger.Debug().Msg("starting")

	for auditResult := range auditResultChan {
		switch res := auditResult.(type) {
		case dtrack.AnalysisRequest:
			submitErr := a.applyAnalysis(ctx, res)
			if submitErr != nil {
				a.logger.Error().Err(submitErr).
					Interface("request", res).
					Msg("failed to apply analysis request")
			}
		case dtrack.ViolationAnalysisRequest:
			submitErr := a.applyViolationAnalysis(ctx, res)
			if submitErr != nil {
				a.logger.Error().Err(submitErr).
					Interface("request", res).
					Msg("failed to apply violation analysis request")
			}
		}
	}

	a.logger.Debug().Str("reason", "audit result channel closed").Msg("stopping")

	return nil
}

// SetDryRun toggles the dry run mode.
// When in dry run mode, analyses will only be logged, but not applied.
func (a *Applier) SetDryRun(dryRun bool) {
	a.dryRun = dryRun
}

// applyAnalysis applies an analysis.
func (a *Applier) applyAnalysis(ctx context.Context, analysisReq dtrack.AnalysisRequest) error {
	var existingAnalysis *dtrack.Analysis
	if analysis, err := a.analysisSvc.Get(ctx, analysisReq.Component, analysisReq.Project, analysisReq.Vulnerability); err == nil {
		existingAnalysis = &analysis
	} else if !errors.Is(err, io.EOF) {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
		totalApplied.WithLabelValues(metricsLabelStatusFailed, metricsLabelTypeFinding).Inc()
		return fmt.Errorf("failed to fetch existing analysis: %w", err)
	}

	if existingAnalysis != nil {
		// Apply statuses of the existing analysis if the policy
		// analysis didn't set them already. If we don't do this,
		// we'll be overriding them to NOT_SET in Dependency-Track.
		if analysisReq.State == "" && existingAnalysis.State != "" {
			analysisReq.State = existingAnalysis.State
		}
		if analysisReq.Justification == "" && existingAnalysis.Justification != "" {
			analysisReq.Justification = existingAnalysis.Justification
		}
		if analysisReq.Response == "" && existingAnalysis.Response != "" {
			analysisReq.Response = existingAnalysis.Response
		}

		// Prevent redundant comments.
		if analysisReq.Comment != "" {
			commentExists := false
			for _, comment := range existingAnalysis.Comments {
				if comment.Comment == analysisReq.Comment {
					commentExists = true
					break
				}
			}
			if commentExists {
				analysisReq.Comment = ""
			}
		}

		if analysisReq.State == existingAnalysis.State && analysisReq.Justification == existingAnalysis.Justification &&
			analysisReq.Response == existingAnalysis.Response && analysisReq.Details == existingAnalysis.Details &&
			analysisReq.Comment == "" && (analysisReq.Suppressed == nil || *analysisReq.Suppressed == existingAnalysis.Suppressed) {
			totalApplied.WithLabelValues(metricsLabelStatusNop, metricsLabelTypeFinding).Inc()
			a.logger.Info().
				Str("component", analysisReq.Component.String()).
				Str("project", analysisReq.Project.String()).
				Str("vulnerability", analysisReq.Vulnerability.String()).
				Msg("analysis is already in desired state")
			return nil
		}
	}

	if a.dryRun {
		a.logger.Info().
			Interface("analysis", analysisReq).
			Msg("DRY RUN - would apply analysis")
		return nil
	}

	a.logger.Info().
		Str("component", analysisReq.Component.String()).
		Str("project", analysisReq.Project.String()).
		Str("vulnerability", analysisReq.Vulnerability.String()).
		Msg("applying analysis")
	_, err := a.analysisSvc.Create(context.Background(), analysisReq)
	if err != nil {
		totalApplied.WithLabelValues(metricsLabelStatusFailed, metricsLabelTypeFinding).Inc()
		return fmt.Errorf("failed to create analysis: %w", err)
	}

	totalApplied.WithLabelValues(metricsLabelStatusSuccess, metricsLabelTypeFinding).Inc()

	return nil
}

// applyViolationAnalysis applies a violation analysis.
func (a *Applier) applyViolationAnalysis(ctx context.Context, analysisReq dtrack.ViolationAnalysisRequest) error {
	var existingAnalysis *dtrack.ViolationAnalysis
	if analysis, err := a.violationAnalysisSvc.Get(ctx, analysisReq.Component, analysisReq.PolicyViolation); err == nil {
		existingAnalysis = &analysis
	} else if !errors.Is(err, io.EOF) {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
		totalApplied.WithLabelValues(metricsLabelStatusFailed, metricsLabelTypeViolation).Inc()
		return fmt.Errorf("failed to fetch existing analysis: %w", err)
	}

	if existingAnalysis != nil {
		// Apply statuses of the existing analysis if the policy
		// analysis didn't set them already. If we don't do this,
		// we'll be overriding them to NOT_SET in Dependency-Track.
		if analysisReq.State == "" && existingAnalysis.State != "" {
			analysisReq.State = existingAnalysis.State
		}

		// Prevent redundant comments.
		if analysisReq.Comment != "" {
			commentExists := false
			for _, comment := range existingAnalysis.Comments {
				if comment.Comment == analysisReq.Comment {
					commentExists = true
					break
				}
			}
			if commentExists {
				analysisReq.Comment = ""
			}
		}

		if analysisReq.State == existingAnalysis.State && analysisReq.Comment == "" &&
			(analysisReq.Suppressed == nil || *analysisReq.Suppressed == existingAnalysis.Suppressed) {
			totalApplied.WithLabelValues(metricsLabelStatusNop, metricsLabelTypeViolation).Inc()
			a.logger.Info().
				Str("component", analysisReq.Component.String()).
				Str("violation", analysisReq.PolicyViolation.String()).
				Msg("violation analysis is already in desired state")
			return nil
		}
	}

	if a.dryRun {
		a.logger.Info().
			Interface("violationAnalysis", analysisReq).
			Msg("DRY RUN - would apply violation analysis")
		return nil
	}

	a.logger.Info().
		Str("component", analysisReq.Component.String()).
		Str("violation", analysisReq.PolicyViolation.String()).
		Msg("applying violation analysis")
	_, err := a.violationAnalysisSvc.Update(context.Background(), analysisReq)
	if err != nil {
		totalApplied.WithLabelValues(metricsLabelStatusFailed, metricsLabelTypeViolation).Inc()
		return fmt.Errorf("failed to update analysis: %w", err)
	}

	totalApplied.WithLabelValues(metricsLabelStatusSuccess, metricsLabelTypeViolation).Inc()

	return nil
}

// analysisService is an interface for parts of the Dependency-Track
// analysis API to make mocking in tests easier.
//
// This interface is implemented by https://pkg.go.dev/github.com/nscuro/dtrack-client#AnalysisService
type analysisService interface {
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dtrack.Analysis, error)
	Create(context.Context, dtrack.AnalysisRequest) (dtrack.Analysis, error)
}

// violationAnalysisService is an interface for parts of the Dependency-Track
// violation analysis API to make mocking in tests easier.
//
// This interface is implemented by https://pkg.go.dev/github.com/nscuro/dtrack-client#ViolationAnalysisService
type violationAnalysisService interface {
	Get(context.Context, uuid.UUID, uuid.UUID) (dtrack.ViolationAnalysis, error)
	Update(context.Context, dtrack.ViolationAnalysisRequest) (dtrack.ViolationAnalysis, error)
}
