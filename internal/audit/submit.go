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

type analysisService interface {
	Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dtrack.Analysis, error)
	Create(context.Context, dtrack.AnalysisRequest) (dtrack.Analysis, error)
}

type violationAnalysisService interface {
	Get(context.Context, uuid.UUID, uuid.UUID) (dtrack.ViolationAnalysis, error)
	Update(context.Context, dtrack.ViolationAnalysisRequest) (dtrack.ViolationAnalysis, error)
}

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
	if analysis, err := s.analysisSvc.Get(ctx, analysisReq.Component, analysisReq.Project, analysisReq.Vulnerability); err != nil && !errors.Is(err, io.EOF) {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
		return fmt.Errorf("failed to fetch existing analysis: %w", err)
	} else {
		existingAnalysis = &analysis
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

		if analysisReq.State == existingAnalysis.State &&
			analysisReq.Justification == existingAnalysis.Justification &&
			analysisReq.Response == existingAnalysis.Response &&
			analysisReq.Comment == "" &&
			(analysisReq.Suppressed == nil || *analysisReq.Suppressed == existingAnalysis.Suppressed) {
			// Analysis is already in desired state, nothing to do.
			return nil
		}
	}

	// Note: Use a context that is decoupled from ctx here!
	// We don't want in-flight requests to be canceled.
	_, err := s.analysisSvc.Create(context.Background(), analysisReq)
	if err != nil {
		return fmt.Errorf("failed to create analysis: %w", err)
	}

	return nil
}

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
	if analysis, err := s.violationAnalysisSvc.Get(ctx, analysisReq.Component, analysisReq.PolicyViolation); err != nil && !errors.Is(err, io.EOF) {
		// Dependency-Track does not respond with a 404 when no analysis was found,
		// but with a 200 and an empty response body instead.
		return fmt.Errorf("failed to fetch existing analysis: %w", err)
	} else {
		existingAnalysis = &analysis
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

		if analysisReq.State == existingAnalysis.State &&
			analysisReq.Comment == "" &&
			(analysisReq.Suppressed == nil || *analysisReq.Suppressed == existingAnalysis.Suppressed) {
			// Analysis is already in desired state, nothing to do.
			return nil
		}
	}

	// Note: Use a context that is decoupled from ctx here!
	// We don't want in-flight requests to be canceled.
	_, err := s.violationAnalysisSvc.Update(context.Background(), analysisReq)
	if err != nil {
		return fmt.Errorf("failed to update analysis: %w", err)
	}

	return nil
}
