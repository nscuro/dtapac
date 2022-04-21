package main

import (
	"context"
	"flag"
	"fmt"
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

	"github.com/nscuro/dtapac/internal/api"
	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
	"github.com/nscuro/dtapac/internal/policy"
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
	fs.StringVar(&opts.FindingPolicyPath, "finding-policy-path", "", "Policy path for findings")
	fs.StringVar(&opts.ViolationPolicyPath, "violation-policy-path", "", "Policy path for violations")
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
	Host                string
	Port                uint
	DTrackURL           string
	DTrackAPIKey        string
	OPAURL              string
	OPABundle           string
	FindingPolicyPath   string
	ViolationPolicyPath string
	AuditWorkers        uint
	LogLevel            string
}

func exec(ctx context.Context, opts options) error {
	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})
	if logLvl, err := zerolog.ParseLevel(opts.LogLevel); err == nil {
		logger = logger.Level(logLvl)
	} else {
		return err
	}

	dtrackClient, err := dtrack.NewClient(opts.DTrackURL, dtrack.WithAPIKey(opts.DTrackAPIKey))
	if err != nil {
		return fmt.Errorf("failed to setup dtrack client: %w", err)
	}

	var (
		findingPolicyEvaler   policy.Evaluator
		violationPolicyEvaler policy.Evaluator
	)
	if opts.FindingPolicyPath != "" {
		findingPolicyEvaler, err = opa.NewPolicyEvaluator(opts.OPAURL, opts.FindingPolicyPath, getSvcLogger("findingPolicyEvaler", logger))
		if err != nil {
			return fmt.Errorf("failed to setup finding policy evaluator: %w", err)
		}
	} else {
		logger.Warn().Msg("no finding policy path configured, will use no-op policy evaluator for findings")
		findingPolicyEvaler = policy.NewNopEvaluator()
	}
	if opts.ViolationPolicyPath != "" {
		violationPolicyEvaler, err = opa.NewPolicyEvaluator(opts.OPAURL, opts.ViolationPolicyPath, getSvcLogger("violationPolicyEvaler", logger))
		if err != nil {
			return fmt.Errorf("failed to setup violation policy evaluator: %w", err)
		}
	} else {
		logger.Warn().Msg("no violation policy path configured, will use no-op policy evaluator for violations")
		violationPolicyEvaler = policy.NewNopEvaluator()
	}

	auditChan := make(chan any, opts.AuditWorkers*2)
	opaStatusChan := make(chan opa.Status, 1)
	eg, egCtx := errgroup.WithContext(ctx)

	srv := api.NewServer(fmt.Sprintf("%s:%d", opts.Host, opts.Port), auditChan, opaStatusChan, getSvcLogger("api", logger))
	eg.Go(srv.Start)

	auditor := audit.NewAuditor(findingPolicyEvaler, violationPolicyEvaler, dtrackClient.Analysis, getSvcLogger("auditor", logger))
	for i := uint(0); i < opts.AuditWorkers; i++ {
		eg.Go(func() error {
			return auditor.Audit(egCtx, auditChan)
		})
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case <-stop:
		logger.Debug().Str("reason", "shutdown requested").Msg("shutting down")
		break
	case <-egCtx.Done():
		logger.Debug().Str("reason", egCtx.Err().Error()).Msg("shutting down")
		break
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = srv.Stop(timeoutCtx)
	if err != nil {
		logger.Err(err).Msg("failed to stop http server")
	}

	logger.Debug().Msg("waiting for workers to stop")
	close(opaStatusChan)
	close(auditChan)
	return eg.Wait()
}

func getSvcLogger(svc string, logger zerolog.Logger) zerolog.Logger {
	return logger.With().Str("svc", svc).Logger()
}
