package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"

	"github.com/nscuro/dtrack-client"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/nscuro/dtapac/internal/api"
	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/model"
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
	fs.UintVar(&opts.AuditWorkers, "audit-workers", 2, "Number of audit workers")

	cmd := ffcli.Command{
		Name: "dtapac",
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
	AuditWorkers        uint
}

func exec(ctx context.Context, opts options) error {
	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})

	dtClient, err := dtrack.NewClient(opts.DTrackURL, dtrack.WithAPIKey(opts.DTrackAPIKey))
	if err != nil {
		return fmt.Errorf("failed to setup dtrack client: %w", err)
	}

	opaClient, err := opa.NewClient(opts.OPAURL)
	if err != nil {
		return fmt.Errorf("failed to setup opa client: %w", err)
	}

	var findingAuditor audit.FindingAuditor = func(finding model.Finding) (analysis model.FindingAnalysis, auditErr error) {
		auditErr = opaClient.Decision(context.Background(), path.Join(opts.FindingPolicyPath, "/analysis"), finding, &analysis)
		return
	}
	var violationAuditor audit.ViolationAuditor = func(violation model.Violation) (analysis model.ViolationAnalysis, auditErr error) {
		auditErr = opaClient.Decision(context.Background(), path.Join(opts.ViolationPolicyPath, "/analysis"), violation, &analysis)
		return
	}

	apiServerAddr := net.JoinHostPort(opts.Host, strconv.FormatUint(uint64(opts.Port), 10))
	apiServer := api.NewServer(apiServerAddr, findingAuditor, violationAuditor, serviceLogger("apiServer", logger))

	submitter := audit.NewSubmitter(dtClient.Analysis, serviceLogger("submitter", logger))

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(apiServer.Start)
	eg.Go(func() error {
		for auditResult := range apiServer.AuditChan() {
			switch res := auditResult.(type) {
			case dtrack.AnalysisRequest:
				err := submitter.SubmitAnalysis(egCtx, res)
				if err != nil {
					logger.Error().Err(err).
						Interface("request", res).
						Msg("failed to submit analysis request")
				}
			}
		}

		return nil
	})

	if opts.WatchBundle != "" {
		bundleWatcher := opa.NewBundleWatcher(opts.WatchBundle, apiServer.OPAStatusChan(), serviceLogger("bundleWatcher", logger))

		eg.Go(func() error {
			return bundleWatcher.Start(egCtx)
		})
	}

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-termChan:
		logger.Debug().Str("reason", "shutdown requested").Msg("shutting down")
	case <-egCtx.Done():
		logger.Debug().Str("reason", egCtx.Err().Error()).Msg("shutting down")
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
