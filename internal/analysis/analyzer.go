package analysis

import (
	"context"
	"fmt"

	"github.com/DependencyTrack/client-go"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/audit"
)

type PortfolioAnalyzer struct {
	dtClient        *dtrack.Client
	auditor         audit.Auditor
	auditResultChan chan any
	logger          zerolog.Logger
}

func NewPortfolioAnalyzer(dtClient *dtrack.Client, auditor audit.Auditor, logger zerolog.Logger) (*PortfolioAnalyzer, error) {
	if dtClient == nil {
		return nil, fmt.Errorf("no dependency-track client provided")
	}
	if auditor == nil {
		return nil, fmt.Errorf("no auditor provided")
	}

	return &PortfolioAnalyzer{
		dtClient:        dtClient,
		auditor:         auditor,
		auditResultChan: make(chan any, 1),
		logger:          logger,
	}, nil
}

// Start listens for messages on triggerChan and launches a portfolio analysis when a trigger is received.
// Upon termination, all channels owned by this PortfolioAnalyzer instance are closed.
// Start is thus intended to only be invoked once.
func (pa PortfolioAnalyzer) Start(ctx context.Context, triggerChan <-chan struct{}) error {
	defer close(pa.auditResultChan)

	pa.logger.Debug().Msg("starting")

	var err error

	for range triggerChan {
		pa.logger.Info().Msg("starting portfolio analysis")

		err = pa.analyzePortfolio(ctx)
		if err == nil {
			pa.logger.Info().Msg("portfolio analysis completed")
		} else {
			pa.logger.Error().Err(err).Msg("portfolio analysis failed")
		}
	}

	pa.logger.Debug().Str("reason", "trigger channel closed").Msg("stopping")

	return nil
}

func (pa PortfolioAnalyzer) analyzePortfolio(ctx context.Context) error {
	pa.logger.Debug().Msg("fetching projects")
	projects, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Project], error) {
		return pa.dtClient.Project.GetAll(ctx, po)
	})
	if err != nil {
		return fmt.Errorf("failed to fetch projects: %w", err)
	}

	for i, project := range projects {
		err = pa.analyzeFindings(ctx, projects[i])
		if err != nil {
			pa.logger.Error().Err(err).
				Str("project", project.UUID.String()).
				Msg("failed to analyze findings")
		}

		err = pa.analyzeViolations(ctx, projects[i])
		if err != nil {
			pa.logger.Error().Err(err).
				Str("project", project.UUID.String()).
				Msg("failed to analyze policy violations")
		}
	}

	return nil
}

func (pa PortfolioAnalyzer) analyzeFindings(ctx context.Context, project dtrack.Project) error {
	pa.logger.Debug().Str("project", project.UUID.String()).Msg("fetching findings")
	findings, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Finding], error) {
		return pa.dtClient.Finding.GetAll(ctx, project.UUID, true, po)
	})
	if err != nil {
		return fmt.Errorf("failed to fetch findings: %w", err)
	}

	for i := range findings {
		finding := audit.NewFinding(findings[i].Component, project, findings[i].Vulnerability)
		analysisReq, auditErr := pa.auditor.AuditFinding(context.Background(), finding)
		if auditErr == nil && analysisReq != (dtrack.AnalysisRequest{}) {
			pa.auditResultChan <- analysisReq
		} else if auditErr != nil {
			return fmt.Errorf("failed to audit finding: %w", auditErr)
		}
	}

	return nil
}

func (pa PortfolioAnalyzer) analyzeViolations(ctx context.Context, project dtrack.Project) error {
	pa.logger.Debug().Str("project", project.UUID.String()).Msg("fetching policy violations")
	violations, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.PolicyViolation], error) {
		return pa.dtClient.PolicyViolation.GetAllForProject(ctx, project.UUID, false, po)
	})
	if err != nil {
		return fmt.Errorf("failed to fetch policy violations: %w", err)
	}

	for i := range violations {
		violation := audit.Violation{
			Component:       violations[i].Component,
			Project:         project,
			PolicyViolation: violations[i],
		}

		analysisReq, auditErr := pa.auditor.AuditViolation(context.Background(), violation)
		if auditErr == nil && analysisReq != (dtrack.ViolationAnalysisRequest{}) {
			pa.auditResultChan <- analysisReq
		} else if auditErr != nil {
			return fmt.Errorf("failed to audit policy violation: %w", auditErr)
		}
	}

	return nil
}

// AuditResultChan returns the analyzer's channel for audit results.
func (pa PortfolioAnalyzer) AuditResultChan() <-chan any {
	return pa.auditResultChan
}
