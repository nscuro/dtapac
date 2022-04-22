package audit

import (
	"context"
	"fmt"
	"path"

	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/nscuro/dtapac/internal/model"
	"github.com/nscuro/dtapac/internal/opa"
)

type Option func(*Auditor)

func WithFindingPolicyPath(policyPath string) Option {
	return func(a *Auditor) {
		a.findingPolicyPath = policyPath
	}
}

func WithViolationPolicyPath(policyPath string) Option {
	return func(a *Auditor) {
		a.violationPolicyPath = policyPath
	}
}

func WithWorkers(workers uint) Option {
	return func(a *Auditor) {
		a.workers = workers
	}
}

func WithLogger(logger zerolog.Logger) Option {
	return func(a *Auditor) {
		a.logger = logger
	}
}

type Auditor struct {
	opaClient           opa.Client
	inputChan           <-chan any
	outputChan          chan any
	findingPolicyPath   string
	violationPolicyPath string
	workers             uint
	logger              zerolog.Logger
}

func NewAuditor(opaClient opa.Client, inputChan <-chan any, opts ...Option) *Auditor {
	auditor := Auditor{
		opaClient:  opaClient,
		inputChan:  inputChan,
		outputChan: make(chan any, 1),
		workers:    1,
		logger:     zerolog.Nop(),
	}

	for _, opt := range opts {
		opt(&auditor)
	}

	return &auditor
}

func (a Auditor) Start(ctx context.Context) error {
	defer close(a.outputChan)

	a.logger.Debug().Msgf("starting %d workers", a.workers)

	eg, egCtx := errgroup.WithContext(ctx)
	for i := uint(0); i < a.workers; i++ {
		workerID := i
		eg.Go(func() error {
			return a.runWorker(egCtx, workerID)
		})
	}

	return eg.Wait()
}

func (a Auditor) OutputChan() <-chan any {
	return a.outputChan
}

func (a Auditor) runWorker(ctx context.Context, workerID uint) error {
	logger := a.logger.With().Uint("workerID", workerID).Logger()

	var (
		input any
		open  bool
	)

	for {
		select {
		case input, open = <-a.inputChan:
			if !open {
				logger.Debug().
					Str("reason", "input channel closed").
					Msg("stopping")
				return nil
			}
		case <-ctx.Done():
			logger.Debug().
				Str("reason", ctx.Err().Error()).
				Msg("stopping")
			return ctx.Err()
		}

		switch item := input.(type) {
		case model.Finding:
			a.auditFinding(ctx, item, logger)
		case model.Violation:
			a.auditViolation(ctx, item, logger)
		default:
			logger.Warn().
				Str("itemType", fmt.Sprintf("%T", input)).
				Msg("cannot audit item of unsupported type")
		}
	}
}

func (a Auditor) auditFinding(ctx context.Context, finding model.Finding, logger zerolog.Logger) {
	logger = logger.With().Object("finding", finding).Logger()

	if a.findingPolicyPath == "" {
		logger.Warn().
			Str("reason", "no policy configured").
			Msg("cannot audit finding")
		return
	}

	var analysis model.FindingAnalysis
	err := a.opaClient.Decision(ctx, path.Join(a.findingPolicyPath, "/analysis"), finding, &analysis)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get policy decision")
		return
	}

	if analysis == (model.FindingAnalysis{}) {
		logger.Debug().Msg("finding is not covered by policy")
	} else {
		a.outputChan <- dtrack.AnalysisRequest{
			Component:     finding.Component.UUID,
			Project:       finding.Project.UUID,
			Vulnerability: finding.Vulnerability.UUID,
			State:         analysis.State,
			Justification: analysis.Justification,
			Response:      analysis.Response,
			Comment:       analysis.Comment,
			Suppressed:    analysis.Suppress,
		}
	}
}

func (a Auditor) auditViolation(ctx context.Context, violation model.Violation, logger zerolog.Logger) {
	logger = logger.With().Object("violation", violation).Logger()

	if a.violationPolicyPath == "" {
		logger.Warn().
			Str("reason", "no policy configured").
			Msg("cannot audit violation")
		return
	}

	var analysis model.ViolationAnalysis
	err := a.opaClient.Decision(ctx, path.Join(a.violationPolicyPath, "/analysis"), violation, &analysis)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get policy decision")
		return
	}

	if analysis == (model.ViolationAnalysis{}) {
		logger.Debug().Msg("violation is not covered by policy")
	} else {
		// TODO
	}
}
