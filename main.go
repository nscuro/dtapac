package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/nscuro/dtrack-client"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/nscuro/dtapac/internal/api"
	"github.com/nscuro/dtapac/internal/apply"
	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

func main() {
	fs := flag.NewFlagSet("dtapac", flag.ContinueOnError)
	fs.String("config", "", "Path to config file")

	var opts options
	fs.StringVar(&opts.Host, "host", "0.0.0.0", "Host to listen on")
	fs.UintVar(&opts.Port, "port", 8080, "Port to listen on")
	fs.StringVar(&opts.DTrackURL, "dtrack-url", "", "Dependency-Track API server URL")
	fs.StringVar(&opts.DTrackAPIKey, "dtrack-apikey", "", "Dependency-Track API key")
	fs.StringVar(&opts.OPAURL, "opa-url", "", "Open Policy Agent URL")
	fs.StringVar(&opts.WatchBundle, "watch-bundle", "", "OPA bundle to watch")
	fs.StringVar(&opts.FindingPolicyPath, "finding-policy-path", "", "Policy path for finding analysis")
	fs.StringVar(&opts.ViolationPolicyPath, "violation-policy-path", "", "Policy path for violation analysis")

	cmd := ffcli.Command{
		Name:       "dtapac",
		ShortUsage: "dtapac [FLAGS...]",
		LongHelp:   `Audit Dependency-Track findings and policy violations via policy as code.`,
		Options: []ff.Option{
			ff.WithEnvVarNoPrefix(),
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithAllowMissingConfigFile(true),
		},
		FlagSet: fs,
		Exec: func(ctx context.Context, _ []string) error {
			return exec(ctx, opts)
		},
	}

	err := cmd.ParseAndRun(context.Background(), os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	Host                string
	Port                uint
	DTrackURL           string
	DTrackAPIKey        string
	OPAURL              string
	WatchBundle         string
	FindingPolicyPath   string
	ViolationPolicyPath string
}

func exec(ctx context.Context, opts options) error {
	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})

	// Setup Dependency-Track client and verify that we can establish a working connection.
	dtrackClient, err := dtrack.NewClient(opts.DTrackURL, dtrack.WithAPIKey(opts.DTrackAPIKey))
	if err != nil {
		return fmt.Errorf("failed to setup dtrack client: %w", err)
	}
	if about, err := dtrackClient.About.Get(ctx); err == nil {
		if version := about.Version; version != "" {
			logger.Info().Msgf("connected to dependency-track %s", version)
		} else {
			return fmt.Errorf("unable to determine dependency-track version, please verify provided url")
		}
	} else {
		return fmt.Errorf("failed to fetch version from dependency-track: %w", err)
	}

	// Setup OPA client and verify that we can establish a working connection.
	opaClient, err := opa.NewClient(opts.OPAURL)
	if err != nil {
		return fmt.Errorf("failed to setup opa client: %w", err)
	}
	err = opaClient.Health(context.Background())
	if err == nil {
		logger.Info().Msg("connected to opa")
	} else {
		return fmt.Errorf("opa health check failed: %w", err)
	}

	auditor, err := audit.NewOPAAuditor(opaClient, opts.FindingPolicyPath, opts.ViolationPolicyPath, serviceLogger("auditor", logger))
	if err != nil {
		return fmt.Errorf("failed to setup auditor: %w", err)
	}

	eg, egCtx := errgroup.WithContext(ctx)

	// Setup and start API server
	apiServerAddr := net.JoinHostPort(opts.Host, strconv.FormatUint(uint64(opts.Port), 10))
	apiServer := api.NewServer(apiServerAddr, dtrackClient, auditor, serviceLogger("apiServer", logger))
	eg.Go(apiServer.Start)

	// Audit results can come from multiple sources (ad-hoc or portfolio-wide analyses).
	// We keep track of them in a slice and merge them later if necessary.
	auditResultChans := []<-chan any{apiServer.AuditResultChan()}

	if opts.WatchBundle != "" {
		bundleWatcher := opa.NewBundleWatcher(opts.WatchBundle, apiServer.OPAStatusChan(), serviceLogger("bundleWatcher", logger))

		// Listen for bundle updates and trigger a portfolio-wide analysis
		// if an update was received.
		triggerChan := make(chan struct{}, 1)
		eg.Go(func() (err error) {
			defer close(triggerChan)

			for range bundleWatcher.Subscribe() {
				select {
				case triggerChan <- struct{}{}:
				default:
				}
			}

			return
		})

		// Listen for triggers from the above goroutine and perform a portfolio-wide
		// analysis when triggered.
		auditChan := make(chan any, 1)
		auditResultChans = append(auditResultChans, auditChan)
		eg.Go(func() error {
			defer close(auditChan)

			for range triggerChan {
				logger.Info().Msg("starting portfolio analysis")

				projects, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Project], error) {
					return dtrackClient.Project.GetAll(egCtx, po)
				})
				if err != nil {
					logger.Error().Err(err).Msg("failed to fetch projects")
					continue
				}

				for i, project := range projects {
					logger.Debug().Str("project", project.UUID.String()).Msg("fetching findings")
					findings, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.Finding], error) {
						return dtrackClient.Finding.GetAll(egCtx, project.UUID, true, po)
					})
					if err != nil {
						logger.Error().Err(err).
							Str("project", project.UUID.String()).
							Msg("failed to fetch findings")
						continue
					}

					for j := range findings {
						finding := audit.Finding{
							Component:     findings[j].Component,
							Project:       projects[i],
							Vulnerability: findings[j].Vulnerability,
						}

						analysisReq, auditErr := auditor.AuditFinding(context.Background(), finding)
						if auditErr == nil && analysisReq != (dtrack.AnalysisRequest{}) {
							auditChan <- analysisReq
						} else if auditErr != nil {
							logger.Error().Err(auditErr).
								Object("finding", finding).
								Msg("failed to audit finding")
							continue
						}
					}

					logger.Debug().Str("project", project.UUID.String()).Msg("fetching policy violations")
					violations, err := dtrack.FetchAll(func(po dtrack.PageOptions) (dtrack.Page[dtrack.PolicyViolation], error) {
						return dtrackClient.PolicyViolation.GetAllForProject(egCtx, project.UUID, false, po)
					})
					if err != nil {
						logger.Error().Err(err).
							Str("project", project.UUID.String()).
							Msg("failed to fetch policy violations")
						continue
					}

					for j := range violations {
						violation := audit.Violation{
							Component:       violations[j].Component,
							Project:         violations[i].Project,
							PolicyViolation: violations[i],
						}

						analysisReq, auditErr := auditor.AuditViolation(context.Background(), violation)
						if auditErr == nil && analysisReq != (dtrack.ViolationAnalysisRequest{}) {
							auditChan <- analysisReq
						} else if auditErr != nil {
							logger.Error().Err(auditErr).
								Object("violation", violation).
								Msg("failed to audit violation")
							continue
						}
					}
				}

				logger.Info().Msg("portfolio analysis completed")
			}

			return nil
		})

		eg.Go(func() error {
			return bundleWatcher.Start(egCtx)
		})
	}

	// If we have more than one channel for audit results, merge them into one.
	// It'd be preferable if we only ever had to deal with one, but that is a little
	// tricky right now when it comes to cancellation and closing channels in the
	// correct order. Worth revisiting later.
	var auditResultChan <-chan any
	if len(auditResultChans) == 1 {
		auditResultChan = auditResultChans[0]
	} else {
		auditResultChan = merge(auditResultChans...)
	}

	applier := apply.NewApplier(dtrackClient.Analysis, dtrackClient.ViolationAnalysis, serviceLogger("applier", logger))
	eg.Go(func() error {
		for auditResult := range auditResultChan {
			switch res := auditResult.(type) {
			case dtrack.AnalysisRequest:
				submitErr := applier.ApplyAnalysis(egCtx, res)
				if submitErr != nil {
					logger.Error().Err(submitErr).
						Interface("request", res).
						Msg("failed to apply analysis request")
				}
			case dtrack.ViolationAnalysisRequest:
				submitErr := applier.ApplyViolationAnalysis(egCtx, res)
				if submitErr != nil {
					logger.Error().Err(submitErr).
						Interface("request", res).
						Msg("failed to apply violation analysis request")
				}
			}
		}

		return nil
	})

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-termChan:
		logger.Debug().Str("reason", "shutdown requested").Msg("shutting down")
	case <-egCtx.Done():
		logger.Debug().AnErr("reason", egCtx.Err()).Msg("shutting down")
	}

	err = apiServer.Stop()
	if err != nil {
		logger.Error().Err(err).Msg("failed to shutdown api server")
	}

	return eg.Wait()
}

func serviceLogger(name string, parent zerolog.Logger) zerolog.Logger {
	return parent.With().Str("svc", name).Logger()
}

// merge converts a list of channels to a single channel, implementing a fan-in operation.
// This code snippet was taken from https://go.dev/blog/pipelines
func merge(cs ...<-chan any) <-chan any {
	var wg sync.WaitGroup
	out := make(chan any, 1)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan any) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
