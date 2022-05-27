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
)

type Submitter struct {
	analysisSvc          analysisService
	violationAnalysisSvc violationAnalysisService
	locker               *locker.Locker
	logger               zerolog.Logger
}

func NewSubmitter(analysisService analysisService, logger zerolog.Logger) *Submitter {
	return &Submitter{
		analysisSvc: analysisService,
		locker:      locker.New(),
		logger:      logger,
	}
}

// SubmitAnalysis submits a dtrack.AnalysisRequest to Dependency-Track.
func (s Submitter) SubmitAnalysis(ctx context.Context, analysisReq dtrack.AnalysisRequest) error {
	lockName := fmt.Sprintf("finding:%s:%s:%s", analysisReq.Component, analysisReq.Project, analysisReq.Vulnerability)
	s.locker.Lock(lockName)
	defer func() {
		err := s.locker.Unlock(lockName)
		if err != nil {
			s.logger.Error().Err(err).
				Str("lock", lockName).
				Msg("failed to unlock")
		}
	}()

	var existingAnalysis *dtrack.Analysis
	if analysis, err := s.analysisSvc.Get(ctx, analysisReq.Component, analysisReq.Project, analysisReq.Vulnerability); err == nil {
		existingAnalysis = &analysis
	} else if !errors.Is(err, io.EOF) {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
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
			s.logger.Info().
				Str("component", analysisReq.Component.String()).
				Str("project", analysisReq.Project.String()).
				Str("vulnerability", analysisReq.Vulnerability.String()).
				Msg("analysis is already in desired state")
			return nil
		}
	}

	s.logger.Info().
		Str("component", analysisReq.Component.String()).
		Str("project", analysisReq.Project.String()).
		Str("vulnerability", analysisReq.Vulnerability.String()).
		Msg("submitting analysis")
	_, err := s.analysisSvc.Create(context.Background(), analysisReq)
	if err != nil {
		return fmt.Errorf("failed to create analysis: %w", err)
	}

	return nil
}

// SubmitViolationAnalysis submits a dtrack.ViolationAnalysisRequest to Dependency-Track.
func (s Submitter) SubmitViolationAnalysis(ctx context.Context, analysisReq dtrack.ViolationAnalysisRequest) error {
	lockName := fmt.Sprintf("violation:%s:%s", analysisReq.Component, analysisReq.PolicyViolation)
	s.locker.Lock(lockName)
	defer func() {
		err := s.locker.Unlock(lockName)
		if err != nil {
			s.logger.Error().Err(err).
				Str("lock", lockName).
				Msg("failed to unlock")
		}
	}()

	var existingAnalysis *dtrack.ViolationAnalysis
	if analysis, err := s.violationAnalysisSvc.Get(ctx, analysisReq.Component, analysisReq.PolicyViolation); err == nil {
		existingAnalysis = &analysis
	} else if !errors.Is(err, io.EOF) {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
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
			s.logger.Info().
				Str("component", analysisReq.Component.String()).
				Str("violation", analysisReq.PolicyViolation.String()).
				Msg("violation analysis is already in desired state")
			return nil
		}
	}

	s.logger.Info().
		Str("component", analysisReq.Component.String()).
		Str("violation", analysisReq.PolicyViolation.String()).
		Msg("submitting violation analysis")
	_, err := s.violationAnalysisSvc.Update(context.Background(), analysisReq)
	if err != nil {
		return fmt.Errorf("failed to update analysis: %w", err)
	}

	return nil
}

// analysisService is an interface for parts of the Dependency-Track
// analysis API to make mocking in tests easier.
//
// This interface is implemented by github.com/nscuro/dtrack-client.
type analysisService interface {
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dtrack.Analysis, error)
	Create(context.Context, dtrack.AnalysisRequest) (dtrack.Analysis, error)
}

// violationAnalysisService is an interface for parts of the Dependency-Track
// violation analysis API to make mocking in tests easier.
//
// This interface is implemented by github.com/nscuro/dtrack-client.
type violationAnalysisService interface {
	Get(context.Context, uuid.UUID, uuid.UUID) (dtrack.ViolationAnalysis, error)
	Update(context.Context, dtrack.ViolationAnalysisRequest) (dtrack.ViolationAnalysis, error)
}
