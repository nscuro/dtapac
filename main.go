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

	"github.com/DependencyTrack/client-go"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/nscuro/dtapac/internal/analysis"
	"github.com/nscuro/dtapac/internal/api"
	"github.com/nscuro/dtapac/internal/apply"
	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

func main() {
	fs := flag.NewFlagSet("dtapac", flag.ContinueOnError)
	fs.String("config", "", "Path to config file")

	var opts options
	fs.StringVar(&opts.host, "host", "0.0.0.0", "Host to listen on")
	fs.UintVar(&opts.port, "port", 8080, "Port to listen on")
	fs.StringVar(&opts.dtURL, "dtrack-url", "", "Dependency-Track API server URL")
	fs.StringVar(&opts.dtAPIKey, "dtrack-apikey", "", "Dependency-Track API key")
	fs.StringVar(&opts.opaURL, "opa-url", "", "Open Policy Agent URL")
	fs.StringVar(&opts.watchBundle, "watch-bundle", "", "OPA bundle to watch")
	fs.StringVar(&opts.findingPolicyPath, "finding-policy-path", "", "Policy path for finding analysis")
	fs.StringVar(&opts.violationPolicyPath, "violation-policy-path", "", "Policy path for violation analysis")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "Only log analyses but don't apply them")
	fs.StringVar(&opts.logLevel, "log-level", zerolog.LevelInfoValue, "Log level")
	fs.BoolVar(&opts.logJSON, "log-json", false, "Output log in JSON format")

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
	host                string
	port                uint
	dtURL               string
	dtAPIKey            string
	opaURL              string
	watchBundle         string
	findingPolicyPath   string
	violationPolicyPath string
	dryRun              bool
	logLevel            string
	logJSON             bool
}

func exec(ctx context.Context, opts options) error {
	logger := log.Logger
	if !opts.logJSON {
		logger = log.Output(zerolog.ConsoleWriter{
			Out: os.Stderr,
		})
	}
	if lvl, err := zerolog.ParseLevel(opts.logLevel); err == nil {
		logger = logger.Level(lvl)
	} else {
		logger.Error().Err(err).Msg("failed to parse log level")
	}

	dtClient, err := dtrack.NewClient(opts.dtURL, dtrack.WithAPIKey(opts.dtAPIKey))
	if err != nil {
		return fmt.Errorf("failed to setup dtrack client: %w", err)
	}

	opaClient, err := opa.NewClient(opts.opaURL)
	if err != nil {
		return fmt.Errorf("failed to setup opa client: %w", err)
	}

	auditor, err := audit.NewOPAAuditor(opaClient, opts.findingPolicyPath, opts.violationPolicyPath, serviceLogger("auditor", logger))
	if err != nil {
		return fmt.Errorf("failed to setup auditor: %w", err)
	}

	apiServerAddr := net.JoinHostPort(opts.host, strconv.FormatUint(uint64(opts.port), 10))
	apiServer, err := api.NewServer(apiServerAddr, dtClient, auditor, serviceLogger("apiServer", logger))
	if err != nil {
		return fmt.Errorf("failed to setup api server: %w", err)
	}

	bundleWatcher, err := opa.NewBundleWatcher(opts.watchBundle, apiServer.OPAStatusChan(), serviceLogger("bundleWatcher", logger))
	if err != nil {
		return fmt.Errorf("failed to setup bundle watcher: %w", err)
	}

	portfolioAnalyzer, err := analysis.NewPortfolioAnalyzer(dtClient, auditor, serviceLogger("portfolioAnalyzer", logger))
	if err != nil {
		return fmt.Errorf("failed to setup portfolio analyzer: %w", err)
	}

	applier := apply.NewApplier(dtClient.Analysis, dtClient.ViolationAnalysis, serviceLogger("applier", logger))
	applier.SetDryRun(opts.dryRun)

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(apiServer.Start)
	eg.Go(func() error {
		return bundleWatcher.Start(egCtx)
	})

	// Trigger a portfolio analysis every time the watched bundle has been updated.
	portfolioAnalysisTriggerChan := make(chan struct{}, 1)
	eg.Go(func() error {
		defer close(portfolioAnalysisTriggerChan)

		for {
			select {
			case _, open := <-bundleWatcher.UpdateChan():
				if !open {
					return nil
				}

				portfolioAnalysisTriggerChan <- struct{}{}
			case <-egCtx.Done():
				return egCtx.Err()
			}
		}
	})

	eg.Go(func() error {
		return portfolioAnalyzer.Start(egCtx, portfolioAnalysisTriggerChan)
	})

	// Merge all channels that emit audit results into one, so the applier can consume them.
	auditResultChan := merge(apiServer.AuditResultChan(), portfolioAnalyzer.AuditResultChan())
	eg.Go(func() error {
		return applier.Start(egCtx, auditResultChan)
	})

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-termChan:
		logger.Debug().Str("reason", "shutdown requested").Msg("shutting down")
	case <-egCtx.Done():
		logger.Debug().AnErr("reason", egCtx.Err()).Msg("shutting down")
	}

	// Stopping the API server will close all its channels, draining all channels
	// further down the processing pipeline and ultimately closing them too.
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
