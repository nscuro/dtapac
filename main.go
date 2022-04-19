package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nscuro/dtrack-client"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/model"
	"github.com/nscuro/dtapac/internal/policy"
	"github.com/nscuro/dtapac/internal/server"
)

func main() {
	err := newCmd().ParseAndRun(context.Background(), os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCmd() *ffcli.Command {
	fs := flag.NewFlagSet("dtapac", flag.ContinueOnError)
	fs.String("config", "", "Path to config file")

	var opts options
	fs.StringVar(&opts.Host, "host", "0.0.0.0", "Host to listen on")
	fs.UintVar(&opts.Port, "port", 8080, "Port to listen on")
	fs.StringVar(&opts.DTrackURL, "dtrack-url", "", "Dependency-Track API server URL")
	fs.StringVar(&opts.DTrackAPIKey, "dtrack-apikey", "", "Dependency-Track API key")
	fs.StringVar(&opts.OPAURL, "opa-url", "", "OPA URL")
	fs.StringVar(&opts.OPABundle, "opa-bundle", "", "OPA bundle to listen for status updates for")
	fs.StringVar(&opts.PolicyPackage, "policy-package", "dtapac", "OPA policy package")
	fs.UintVar(&opts.AuditWorkers, "audit-workers", 2, "Number of workers to perform auditing")
	fs.StringVar(&opts.LogLevel, "log-level", zerolog.LevelInfoValue, "Log level")

	return &ffcli.Command{
		Name:       "dtapac",
		ShortUsage: "dtapac [FLAGS...]",
		LongHelp:   "Audit Dependency-Track findings via policy as code.",
		FlagSet:    fs,
		Options: []ff.Option{
			ff.WithEnvVarPrefix("DTAPAC"),
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithAllowMissingConfigFile(true),
		},
		Exec: func(ctx context.Context, _ []string) error {
			return exec(ctx, opts)
		},
	}
}

type options struct {
	Host          string
	Port          uint
	DTrackURL     string
	DTrackAPIKey  string
	OPAURL        string
	OPABundle     string
	PolicyPackage string
	AuditWorkers  uint
	LogLevel      string
}

func exec(ctx context.Context, opts options) error {
	// Setup logger.
	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})
	if logLvl, err := zerolog.ParseLevel(opts.LogLevel); err == nil {
		logger = logger.Level(logLvl)
	} else {
		return err
	}

	// Setup channels.
	findingsChan := make(chan model.Finding, opts.AuditWorkers*2)
	portfolioAnalysisChan := make(chan struct{})

	// Setup Dependency-Track client.
	dtrackClient, err := dtrack.NewClient(opts.DTrackURL, dtrack.WithAPIKey(opts.DTrackAPIKey))
	if err != nil {
		return fmt.Errorf("failed to setup dtrack client: %w", err)
	}

	// Setup HTTP server.
	srvLogger := getSvcLogger("server", logger)
	srvOptions := []server.Option{
		server.WithLogger(srvLogger),
		server.WithHandler(http.MethodPost, "/notification/finding", server.NewFindingHandler(findingsChan, srvLogger)),
	}
	if opts.OPABundle != "" {
		logger.Debug().Str("bundle", opts.OPABundle).Msg("will listen for opa bundle status updates")
		srvOptions = append(srvOptions, server.WithHandler(http.MethodPost, "/opa/status", server.NewOPABundleStatusHandler(opts.OPABundle, portfolioAnalysisChan, srvLogger)))
	}
	srv, err := server.New(fmt.Sprintf("%s:%d", opts.Host, opts.Port), srvOptions...)
	if err != nil {
		return fmt.Errorf("failed to setup server: %w", err)
	}

	// Setup policy evaluator.
	policyEvaler, err := policy.NewOPAEvaluator(opts.OPAURL, opts.PolicyPackage, getSvcLogger("policyEvaler", logger))
	if err != nil {
		return fmt.Errorf("failed to setup policy evaluator: %w", err)
	}

	// Setup auditor.
	auditor := audit.NewAuditor(policyEvaler, dtrackClient.Analysis, getSvcLogger("auditor", logger))

	// Launch worker goroutines.
	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(srv.Run)
	for i := uint(0); i < opts.AuditWorkers; i++ {
		eg.Go(auditWorker(egCtx, findingsChan, auditor, getSvcLogger("auditWorker", logger).With().Uint("workerID", i).Logger()))
	}
	eg.Go(portfolioAnalysisWorker(egCtx, portfolioAnalysisChan, findingsChan, dtrackClient, getSvcLogger("portfolioAnalysisWorker", logger)))

	// Wait for interrupt signal.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Debug().Msg("shutting down")

	// Gracefully shutdown HTTP server.
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = srv.Stop(timeoutCtx)
	if err != nil {
		logger.Err(err).Msg("failed to stop http server")
	}

	// Close channels and wait for all pending work to be completed.
	logger.Debug().Msg("waiting for workers to stop")
	close(portfolioAnalysisChan)
	close(findingsChan)
	return eg.Wait()
}

// auditWorker consumes findings from a channel and audits them.
func auditWorker(ctx context.Context, findingsChan <-chan model.Finding, auditor *audit.Auditor, logger zerolog.Logger) func() error {
	return func() error {
		var (
			finding model.Finding
			hasMore bool
			err     error
		)

		for {
			select {
			case finding, hasMore = <-findingsChan:
				if !hasMore {
					logger.Debug().Str("reason", "channel closed").Msg("stopping")
					return nil
				}
				break
			case <-ctx.Done():
				logger.Debug().Str("reason", "canceled").Msg("stopping")
				return ctx.Err()
			}

			err = auditor.AuditFinding(ctx, finding)
			if err != nil {
				logger.Error().Err(err).Msg("failed to audit finding")
			}
		}
	}
}

// portfolioAnalysisWorker listens for triggers on analysisChan and submits all findings in the portfolio for analysis.
// Triggers are sent whenever OPA pulls a new version of the policy bundle, for example.
func portfolioAnalysisWorker(ctx context.Context, analysisChan <-chan struct{}, findingsChan chan<- model.Finding, dtrackClient *dtrack.Client, logger zerolog.Logger) func() error {
	return func() error {
		var hasMore bool

		for {
			select {
			case _, hasMore = <-analysisChan:
				if !hasMore {
					logger.Debug().Str("reason", "channel closed").Msg("stopping")
					return nil
				}
				break
			case <-ctx.Done():
				logger.Debug().Str("reason", "canceled").Msg("stopping")
				return ctx.Err()
			}

			logger.Info().Msg("starting portfolio analysis")

			var (
				projectsPageNumber = 1
				projectsSeen       = 0
			)
			for {
				projectsPage, err := dtrackClient.Project.GetAll(ctx, dtrack.PageOptions{
					PageNumber: projectsPageNumber,
					PageSize:   25,
				})
				if err != nil {
					logger.Error().Err(err).Int("pageNumber", projectsPageNumber).Msg("failed to fetch projects")
					break
				}

				for i := range projectsPage.Projects {
					project := projectsPage.Projects[i]
					logger.Info().Str("project", project.UUID.String()).Msg("starting project analysis")

					var (
						findingsPageNumber = 1
						findingsSeen       = 0
					)
					for {
						findingsPage, err := dtrackClient.Finding.GetAll(ctx, project.UUID, true, dtrack.PageOptions{
							PageNumber: findingsPageNumber,
							PageSize:   25,
						})
						if err != nil {
							logger.Error().Err(err).
								Str("project", project.UUID.String()).
								Int("pageNumber", findingsPageNumber).
								Msg("failed to fetch findings")
							break
						}

						for j := range findingsPage.Findings {
							finding := findingsPage.Findings[j]

							findingsChan <- model.Finding{
								Component:     finding.Component,
								Project:       project,
								Vulnerability: finding.Vulnerability,
							}
						}

						findingsSeen += len(findingsPage.Findings)
						if findingsSeen >= findingsPage.TotalCount {
							break
						}
					}

					logger.Info().Str("project", project.UUID.String()).Msg("project analysis completed")
				}

				projectsSeen += len(projectsPage.Projects)
				if projectsSeen >= projectsPage.TotalCount {
					break
				}
			}

			logger.Info().Msg("portfolio analysis completed")
		}
	}
}

func getSvcLogger(svc string, logger zerolog.Logger) zerolog.Logger {
	return logger.With().Str("svc", svc).Logger()
}
